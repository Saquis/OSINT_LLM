from neo4j import GraphDatabase
from typing import List, Dict
import os

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "osint2026")

class Neo4jClient:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    def close(self):
        self.driver.close()

    def create_indexes(self):
        with self.driver.session() as session:
            session.run("CREATE INDEX domain_name IF NOT EXISTS FOR (d:Domain) ON (d.name)")
            session.run("CREATE INDEX subdomain_name IF NOT EXISTS FOR (s:Subdomain) ON (s.name)")
            session.run("CREATE INDEX ip_address IF NOT EXISTS FOR (i:IP) ON (i.address)")
            session.run("CREATE INDEX email_address IF NOT EXISTS FOR (e:Email) ON (e.address)")
            session.run("CREATE INDEX credential_value IF NOT EXISTS FOR (c:Credential) ON (c.value)")

    # ── Nodos ──────────────────────────────────────────────────────────────
    def add_domain(self, name: str) -> None:
        with self.driver.session() as session:
            session.run("MERGE (d:Domain {name: $name})", name=name)

    def add_subdomain(self, name: str, domain: str) -> None:
        with self.driver.session() as session:
            session.run("""
                MERGE (s:Subdomain {name: $name})
                MERGE (d:Domain {name: $domain})
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """, name=name, domain=domain)

    def add_ip(self, address: str, subdomain: str) -> None:
        with self.driver.session() as session:
            session.run("""
                MERGE (i:IP {address: $address})
                MERGE (s:Subdomain {name: $subdomain})
                MERGE (s)-[:RESOLVES_TO]->(i)
            """, address=address, subdomain=subdomain)

    def add_email(self, address: str, domain: str, source: str = "") -> None:
        with self.driver.session() as session:
            session.run("""
                MERGE (e:Email {address: $address})
                SET e.source = $source
                MERGE (d:Domain {name: $domain})
                MERGE (d)-[:HAS_EMAIL]->(e)
            """, address=address, domain=domain, source=source)

    def add_credential(self, value: str, email: str = "", is_real: bool = False, confidence: float = 0.0) -> None:
        with self.driver.session() as session:
            session.run("""
                MERGE (c:Credential {value: $value})
                SET c.is_real = $is_real, c.confidence = $confidence
            """, value=value, is_real=is_real, confidence=confidence)
            if email:
                session.run("""
                    MERGE (e:Email {address: $email})
                    MERGE (c:Credential {value: $value})
                    MERGE (e)-[:HAS_CREDENTIAL]->(c)
                """, email=email, value=value)

    def add_vulnerability(self, subdomain: str, description: str, cvss: float, severity: str) -> None:
        with self.driver.session() as session:
            session.run("""
                MERGE (v:Vulnerability {description: $description})
                SET v.cvss = $cvss, v.severity = $severity
                MERGE (s:Subdomain {name: $subdomain})
                MERGE (s)-[:HAS_VULNERABILITY]->(v)
            """, subdomain=subdomain, description=description, cvss=cvss, severity=severity)

    # ── Queries analíticas ─────────────────────────────────────────────────
    def get_attack_surface(self, domain: str) -> Dict:
        with self.driver.session() as session:
            subdomains = session.run("""
                MATCH (d:Domain {name: $domain})-[:HAS_SUBDOMAIN]->(s:Subdomain)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
                RETURN s.name as subdomain, collect(i.address) as ips
            """, domain=domain).data()

            emails = session.run("""
                MATCH (d:Domain {name: $domain})-[:HAS_EMAIL]->(e:Email)
                RETURN e.address as email, e.source as source
            """, domain=domain).data()

            vulns = session.run("""
                MATCH (d:Domain {name: $domain})-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                RETURN s.name as subdomain, v.description as vuln, v.cvss as cvss, v.severity as severity
                ORDER BY v.cvss DESC
            """, domain=domain).data()

            return {
                "domain": domain,
                "subdomains": subdomains,
                "emails": emails,
                "vulnerabilities": vulns
            }

    def find_attack_path(self, start: str, end: str) -> List:
        with self.driver.session() as session:
            result = session.run("""
                MATCH path = shortestPath(
                    (a {name: $start})-[*]-(b {name: $end})
                )
                RETURN [node in nodes(path) | coalesce(node.name, node.address)] as path
            """, start=start, end=end).data()
            return result

    def get_shared_infrastructure(self, domain: str) -> List:
        with self.driver.session() as session:
            return session.run("""
                MATCH (s1:Subdomain)-[:RESOLVES_TO]->(i:IP)<-[:RESOLVES_TO]-(s2:Subdomain)
                WHERE s1.name <> s2.name
                AND (s1.name CONTAINS $domain OR s2.name CONTAINS $domain)
                RETURN i.address as ip, collect(DISTINCT s1.name) + collect(DISTINCT s2.name) as subdomains
            """, domain=domain).data()

    def get_critical_nodes(self, domain: str) -> List:
        with self.driver.session() as session:
            return session.run("""
                MATCH (n)-[r]-()
                WHERE n.name CONTAINS $domain OR n.address IS NOT NULL
                RETURN n.name as node, count(r) as connections
                ORDER BY connections DESC
                LIMIT 10
            """, domain=domain).data()