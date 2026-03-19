from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

def print_banner():
    banner_text = Text()
    banner_text.append("X-AUTH AI\n", style="bold white")
    banner_text.append("Credential Intelligence Engine\n", style="dim")
    banner_text.append("National Hackathon Edition", style="italic dim")
    
    console.print(Panel(
        banner_text,
        title="[bold]v1.0.0[/bold]",
        subtitle="[dim]For authorized security testing only[/dim]",
        border_style="bright_blue",
        padding=(1, 4)
    ))