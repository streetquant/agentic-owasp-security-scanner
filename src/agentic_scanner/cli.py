from typer import Typer

app = Typer(help="Agentic OWASP Security Scanner CLI")

@app.command()
def help_cmd():
    print("Use 'agentic-scanner scan <url>' to start a scan.")

def main():
    app()
