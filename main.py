import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from src.scraper.pipeline import OSINTPipeline

console = Console()

BANNER = """
 ██████╗ ███████╗██╗███╗   ██╗████████╗    ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
██║   ██║███████╗██║██╔██╗ ██║   ██║       █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗
██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝
╚██████╔╝███████║██║██║ ╚████║   ██║       ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝
"""

def print_banner():
    console.print(BANNER, style="bold cyan")
    console.print(Panel(
        "[bold white]Motor OSINT Multi-fuente con LLM[/bold white]\n"
        "[dim]Async Scraping + LLM Analysis + Graph Correlation[/dim]\n"
        "[dim]saquis@parrot | Parrot OS 7.1 Echo[/dim]",
        border_style="cyan"
    ))

def parse_args():
    parser = argparse.ArgumentParser(
        description="Motor OSINT Multi-fuente con LLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python main.py --target empresa.com
  python main.py --target empresa.com --engine bing
  python main.py --target empresa.com --no-llm
        """
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Dominio objetivo (ej: empresa.com)"
    )
    parser.add_argument(
        "--engine", "-e",
        choices=["duckduckgo", "bing"],
        default="duckduckgo",
        help="Motor de busqueda (default: duckduckgo)"
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Desactivar analisis LLM (solo scraping)"
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=10,
        help="Limite de URLs a scrapear (default: 10)"
    )
    return parser.parse_args()

def main():
    print_banner()
    args = parse_args()

    console.print(f"\n[bold yellow]Target:[/bold yellow] {args.target}")
    console.print(f"[bold yellow]Engine:[/bold yellow] {args.engine}")
    console.print(f"[bold yellow]LLM:[/bold yellow] {'Desactivado' if args.no_llm else 'Activado (qwen2.5:7b)'}")
    console.print(f"[bold yellow]URL limit:[/bold yellow] {args.limit}\n")

    try:
        pipeline = OSINTPipeline(
            target=args.target,
            engine=args.engine,
            use_llm=not args.no_llm,
            url_limit=args.limit
        )
        pipeline.run()

    except KeyboardInterrupt:
        console.print("\n[bold red]Interrumpido por el usuario.[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()