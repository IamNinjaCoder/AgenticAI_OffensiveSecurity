"""
Agentic AI Reconnaissance System for Cybersecurity
Using CrewAI framework to automate reconnaissance on target domains

Author: AI Assistant
Date: September 2025
Purpose: Educational demonstration for ethical hacking and penetration testing

IMPORTANT: This code is for educational and authorized testing purposes only.
Always ensure you have proper authorization before running reconnaissance on any target.
"""

import os
import subprocess
import json
import requests
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass
from crewai import Agent, Task, Crew
from crewai_tools import SerperDevTool, WebsiteSearchTool
from langchain_openai import ChatOpenAI

# Configuration
@dataclass
class ReconConfig:
    target_domain: str
    output_dir: str = "./recon_results"
    openai_api_key: str = None
    serper_api_key: str = None
    max_subdomains: int = 100
    ethical_mode: bool = True

class EthicalReconSystem:
    """
    Ethical Reconnaissance System using AI Agents

    This system follows responsible disclosure principles and ethical hacking guidelines.
    """

    def __init__(self, config: ReconConfig):
        self.config = config
        self.results = {}

        # Initialize LLM
        self.llm = ChatOpenAI(
            openai_api_key=config.openai_api_key,
            model_name="gpt-4o-mini",
            temperature=0
        )

        # Initialize tools
        self.search_tool = SerperDevTool(api_key=config.serper_api_key)
        self.web_search_tool = WebsiteSearchTool()

        # Create output directory
        os.makedirs(config.output_dir, exist_ok=True)

    def create_agents(self):
        """Create specialized AI agents for different reconnaissance tasks"""

        # OSINT Collection Agent
        osint_agent = Agent(
            role="OSINT Intelligence Analyst",
            goal=f"Gather comprehensive open-source intelligence about {self.config.target_domain} using ethical methods",
            backstory="""You are an experienced OSINT analyst specializing in ethical information gathering. 
            You follow strict ethical guidelines and only collect publicly available information. 
            You respect privacy and legal boundaries while conducting thorough research.""",
            tools=[self.search_tool, self.web_search_tool],
            llm=self.llm,
            verbose=True
        )

        # Subdomain Discovery Agent
        subdomain_agent = Agent(
            role="Subdomain Discovery Specialist",
            goal=f"Discover subdomains for {self.config.target_domain} using passive reconnaissance techniques",
            backstory="""You are a subdomain enumeration expert who uses only passive techniques 
            to discover subdomains. You rely on public databases, search engines, and certificate 
            transparency logs to find subdomains without directly probing the target.""",
            tools=[self.search_tool],
            llm=self.llm,
            verbose=True
        )

        # Technology Stack Analyst
        tech_agent = Agent(
            role="Technology Stack Analyst",
            goal=f"Identify web technologies and frameworks used by {self.config.target_domain}",
            backstory="""You are a web technology specialist who can identify frameworks, 
            CMS platforms, server technologies, and other technical details from publicly 
            available information and standard web requests.""",
            tools=[self.web_search_tool],
            llm=self.llm,
            verbose=True
        )

        # Security Assessment Agent
        security_agent = Agent(
            role="Security Assessment Analyst",
            goal=f"Assess the security posture of {self.config.target_domain} using ethical methods",
            backstory="""You are an ethical security researcher who identifies potential 
            security issues using only passive reconnaissance and publicly available information. 
            You follow responsible disclosure principles and focus on helping improve security.""",
            tools=[self.search_tool, self.web_search_tool],
            llm=self.llm,
            verbose=True
        )

        # Report Generation Agent
        report_agent = Agent(
            role="Cybersecurity Report Writer",
            goal="Create comprehensive and actionable security reconnaissance reports",
            backstory="""You are a skilled cybersecurity report writer who creates detailed, 
            professional reports for security teams. You focus on actionable insights and 
            follow industry best practices for security documentation.""",
            llm=self.llm,
            verbose=True
        )

        return {
            'osint': osint_agent,
            'subdomain': subdomain_agent,
            'tech': tech_agent,
            'security': security_agent,
            'report': report_agent
        }

    def create_tasks(self, agents):
        """Create tasks for each agent"""

        # OSINT Collection Task
        osint_task = Task(
            description=f"""
            Conduct comprehensive OSINT research on {self.config.target_domain}:
            1. Gather basic domain information (WHOIS data, registration details)
            2. Search for publicly available information about the organization
            3. Look for social media presence and public communications
            4. Identify key personnel and contact information (publicly available)
            5. Search for any security-related news or incidents
            6. Document all sources and ensure all information is from public sources

            Focus on ethical collection methods and respect privacy boundaries.
            """,
            agent=agents['osint'],
            expected_output="Detailed OSINT report with sources and methodology"
        )

        # Subdomain Discovery Task
        subdomain_task = Task(
            description=f"""
            Discover subdomains for {self.config.target_domain} using passive methods:
            1. Use search engines to find subdomains
            2. Check certificate transparency logs
            3. Search public DNS databases
            4. Look for subdomains in public code repositories
            5. Validate discovered subdomains (without aggressive probing)
            6. Limit results to {self.config.max_subdomains} most relevant subdomains

            Use only passive reconnaissance techniques.
            """,
            agent=agents['subdomain'],
            expected_output="List of discovered subdomains with discovery methods"
        )

        # Technology Stack Analysis Task
        tech_task = Task(
            description=f"""
            Analyze the technology stack of {self.config.target_domain}:
            1. Identify web server and framework information from headers
            2. Detect CMS platforms and versions (if publicly visible)
            3. Analyze publicly available JavaScript and CSS for technology clues
            4. Check for standard technology fingerprints in public responses
            5. Document security headers and configurations
            6. Note any publicly disclosed technology information

            Use only information available through standard web requests.
            """,
            agent=agents['tech'],
            expected_output="Technology stack analysis with security implications"
        )

        # Security Assessment Task
        security_task = Task(
            description=f"""
            Assess security posture of {self.config.target_domain} ethically:
            1. Check for common security headers and configurations
            2. Look for publicly disclosed vulnerabilities or security advisories
            3. Analyze SSL/TLS configuration using public tools
            4. Search for security-related public disclosures
            5. Check for presence in threat intelligence feeds (if publicly available)
            6. Review security best practices implementation (visible aspects only)

            Focus on passive assessment and publicly available security information.
            """,
            agent=agents['security'],
            expected_output="Security assessment report with recommendations",
            context=[osint_task, subdomain_task, tech_task]
        )

        # Report Generation Task
        report_task = Task(
            description=f"""
            Create a comprehensive reconnaissance report for {self.config.target_domain}:
            1. Summarize all findings from OSINT, subdomain, technology, and security analysis
            2. Organize information in a professional security report format
            3. Include executive summary with key findings
            4. Provide actionable recommendations for security improvements
            5. Document methodology and ethical considerations
            6. Include disclaimers about responsible use and legal compliance
            7. Format the report in both human-readable and structured data formats

            Ensure the report follows professional cybersecurity reporting standards.
            """,
            agent=agents['report'],
            expected_output="Professional cybersecurity reconnaissance report",
            context=[osint_task, subdomain_task, tech_task, security_task]
        )

        return [osint_task, subdomain_task, tech_task, security_task, report_task]

    def run_reconnaissance(self):
        """Execute the reconnaissance workflow"""

        print(f"[+] Starting ethical reconnaissance on: {self.config.target_domain}")
        print(f"[+] Results will be saved to: {self.config.output_dir}")

        # Create agents and tasks
        agents = self.create_agents()
        tasks = self.create_tasks(agents)

        # Create and execute crew
        crew = Crew(
            agents=list(agents.values()),
            tasks=tasks,
            verbose=True
        )

        # Execute the workflow
        print("[+] Executing reconnaissance workflow...")
        result = crew.kickoff()

        # Save results
        self.save_results(result)

        return result

    def save_results(self, result):
        """Save reconnaissance results to files"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save raw results
        with open(f"{self.config.output_dir}/recon_{self.config.target_domain}_{timestamp}.txt", 'w') as f:
            f.write(str(result))

        # Save structured data (if applicable)
        try:
            structured_data = {
                "target": self.config.target_domain,
                "timestamp": timestamp,
                "results": str(result),
                "ethical_compliance": True,
                "methodology": "Passive OSINT and ethical reconnaissance"
            }

            with open(f"{self.config.output_dir}/recon_{self.config.target_domain}_{timestamp}.json", 'w') as f:
                json.dump(structured_data, f, indent=2)

        except Exception as e:
            print(f"[!] Error saving structured data: {e}")

        print(f"[+] Results saved to {self.config.output_dir}")

class TraditionalReconTools:
    """
    Traditional reconnaissance tools integration for comparison and validation
    """

    @staticmethod
    def run_whois(domain: str) -> str:
        """Run WHOIS lookup"""
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
            return result.stdout
        except Exception as e:
            return f"WHOIS lookup failed: {e}"

    @staticmethod
    def run_nslookup(domain: str) -> str:
        """Run DNS lookup"""
        try:
            result = subprocess.run(['nslookup', domain], capture_output=True, text=True, timeout=30)
            return result.stdout
        except Exception as e:
            return f"DNS lookup failed: {e}"

    @staticmethod
    def check_subdomain_with_tools(domain: str) -> List[str]:
        """
        Example of how to integrate traditional tools
        Note: These tools should be installed separately
        """
        subdomains = []

        # Example with Subfinder (if installed)
        try:
            result = subprocess.run(['subfinder', '-d', domain, '-silent'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                subdomains.extend(result.stdout.strip().split(''))
        except:
            pass

        return subdomains

# Usage example and main execution
def main():
    """
    Main function to demonstrate the agentic reconnaissance system
    """

    print("=" * 60)
    print("AGENTIC AI RECONNAISSANCE SYSTEM")
    print("=" * 60)
    print()
    print("LEGAL DISCLAIMER:")
    print("This tool is for educational and authorized testing purposes only.")
    print("Always ensure you have proper authorization before testing any target.")
    print("Follow responsible disclosure practices and respect legal boundaries.")
    print("=" * 60)
    print()

    # Configuration
    target_domain = input("Enter target domain (e.g., hash13.com): ").strip()

    if not target_domain:
        print("[!] No target domain specified. Using example.com for demonstration.")
        target_domain = "example.com"

    # Check for API keys (you'll need to set these)
    openai_key = os.getenv('OPENAI_API_KEY')
    serper_key = os.getenv('SERPER_API_KEY')

    if not openai_key or not serper_key:
        print("[!] Warning: API keys not set. Please set OPENAI_API_KEY and SERPER_API_KEY environment variables.")
        print("[!] This demo will show the structure but may not execute fully without API keys.")

    # Create configuration
    config = ReconConfig(
        target_domain=target_domain,
        output_dir=f"./recon_results_{target_domain}",
        openai_api_key=openai_key,
        serper_api_key=serper_key,
        max_subdomains=50,
        ethical_mode=True
    )

    # Initialize and run reconnaissance system
    try:
        recon_system = EthicalReconSystem(config)

        # Run traditional tools for comparison (optional)
        print("[+] Running traditional reconnaissance tools...")
        traditional_tools = TraditionalReconTools()
        whois_data = traditional_tools.run_whois(target_domain)
        dns_data = traditional_tools.run_nslookup(target_domain)

        print(f"[+] WHOIS data length: {len(whois_data)} characters")
        print(f"[+] DNS data length: {len(dns_data)} characters")

        # Run AI-powered reconnaissance
        print("[+] Starting AI-powered reconnaissance...")

        if openai_key and serper_key:
            result = recon_system.run_reconnaissance()
            print("[+] Reconnaissance completed successfully!")
            return result
        else:
            print("[!] Skipping AI reconnaissance due to missing API keys.")
            print("[!] Set OPENAI_API_KEY and SERPER_API_KEY to run full system.")
            return None

    except Exception as e:
        print(f"[!] Error during reconnaissance: {e}")
        return None

if __name__ == "__main__":
    result = main()
