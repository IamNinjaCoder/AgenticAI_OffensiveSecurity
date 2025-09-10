"""
Advanced Local Tool-Based Agentic Reconnaissance System - CORRECTED VERSION
Using CrewAI with subprocess integration for offline reconnaissance

This system integrates local tools like nmap, sublist3r, whois, nuclei, etc.
with AI agents that can execute commands, analyze outputs, and make intelligent decisions.

Author: ninjahacker
Date: September 2025
Version: 2.1 - Fixed Version with Proper Tool Integration

CRITICAL SECURITY NOTICE:
- This code is for authorized penetration testing only
- Always obtain written permission before testing any target
- Use only on systems you own or have explicit authorization to test
- Follow responsible disclosure practices
"""

import subprocess
import json
import os
import sys
import time
import shlex
import tempfile
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import logging
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

# CrewAI and LangChain imports
try:
    from crewai import Agent, Task, Crew, Process
    from crewai.tools import BaseTool
    from langchain_openai import ChatOpenAI
    from pydantic import BaseModel, Field
except ImportError as e:
    print(f"❌ Missing dependencies. Please install: pip install crewai crewai-tools langchain-openai")
    print(f"Error: {e}")
    sys.exit(1)

# Configuration
@dataclass
class LocalReconConfig:
    target_domain: str
    output_dir: str = "./local_recon_results"
    max_threads: int = 5
    timeout: int = 300  # 5 minutes default timeout
    verbose: bool = True
    save_raw_output: bool = True
    ethical_mode: bool = True

class CommandExecutionResult:
    """Container for command execution results"""
    def __init__(self, command: str, returncode: int, stdout: str, stderr: str, execution_time: float):
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.execution_time = execution_time
        self.timestamp = datetime.now()
        self.success = returncode == 0

class SecureCommandExecutor:
    """
    Secure command executor with safety checks and sandboxing
    """

    # Whitelist of allowed commands for security
    ALLOWED_COMMANDS = {
        'nmap', 'whois', 'dig', 'nslookup', 'ping', 'traceroute',
        'sublist3r', 'subfinder', 'amass', 'assetfinder', 'findomain',
        'theharvester', 'recon-ng', 'whatweb', 'wafw00f', 'nuclei',
        'gobuster', 'dirb', 'nikto', 'curl', 'wget', 'host',
        'dnsrecon', 'fierce', 'masscan', 'zmap', 'httprobe',
        'httpx', 'waybackurls', 'gau', 'unfurl', 'anew', 'which','sudo'
    }

    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        'rm -rf', 'del /f', 'format', 'mkfs', 'dd if=', 
        '> /dev/', 'chmod 777', 'chown root', 'sudo su',
        'wget http', 'curl http', '&amp;&amp;', '||', ';', '`',
        'nc -l', 'netcat -l', 'bash -i', '/bin/sh', 'python -c'
    ]

    def __init__(self, config: LocalReconConfig):
        self.config = config
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Setup secure logging"""
        logger = logging.getLogger("SecureCommandExecutor")
        logger.setLevel(logging.INFO if self.config.verbose else logging.WARNING)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def validate_command(self, command: str) -> bool:
        """Validate command for security"""
        # Check if command starts with allowed command
        cmd_parts = shlex.split(command.lower())
        if not cmd_parts:
            return False

        base_command = cmd_parts[0].split('/')[-1]  # Handle full paths

        if base_command not in self.ALLOWED_COMMANDS:
            self.logger.warning(f"Command not in whitelist: {base_command}")
            return False

        # Check for dangerous patterns
        command_lower = command.lower()
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in command_lower:
                self.logger.error(f"Dangerous pattern detected: {pattern}")
                return False

        return True

    def execute_command(self, command: str, target_validation: bool = True) -> CommandExecutionResult:
        """
        Securely execute a command with proper validation and sandboxing
        """
        start_time = time.time()

        try:
            # Validate command
            if not self.validate_command(command):
                raise ValueError(f"Command validation failed: {command}")

            # Additional target validation for ethical hacking
            if target_validation and self.config.ethical_mode:
                if not self._validate_target_authorization(command):
                    raise ValueError(f"Target not authorized for testing: {command}")

            self.logger.info(f"Executing: {command}")

            # Execute with security constraints
            result = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
                cwd=self.config.output_dir,
                env=self._get_safe_environment()
            )

            execution_time = time.time() - start_time

            cmd_result = CommandExecutionResult(
                command=command,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                execution_time=execution_time
            )

            self.logger.info(f"Command completed in {execution_time:.2f}s with code {result.returncode}")

            return cmd_result

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            self.logger.error(f"Command timed out after {self.config.timeout}s: {command}")
            return CommandExecutionResult(command, -1, "", "Command timed out", execution_time)

        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Command execution error: {e}")
            return CommandExecutionResult(command, -1, "", str(e), execution_time)

    def _validate_target_authorization(self, command: str) -> bool:
        """
        Validate that the target in the command is authorized for testing
        """
        # Extract domain from command if possible
        if self.config.target_domain.lower() in command.lower():
            return True

        # For demonstration, we'll allow localhost and private IPs for testing
        authorized_patterns = [
            'localhost', '127.0.0.1', '192.168.', '10.0.', '172.16.','184.168.'
        ]

        return any(pattern in command for pattern in authorized_patterns)

    def _get_safe_environment(self) -> dict:
        """Get a safe environment for command execution"""
        # Minimal environment to reduce attack surface
        safe_env = {
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin',
            'HOME': self.config.output_dir,
            'TMPDIR': self.config.output_dir,
            'LANG': 'C',
            'LC_ALL': 'C'
        }
        return safe_env

# Custom CrewAI Tools for Local Reconnaissance - CORRECTED VERSIONS
class NmapTool(BaseTool):
    """Nmap port scanning and service detection tool"""
    name: str = "nmap_scanner"
    description: str = "Execute Nmap scans for port discovery, service detection, and OS fingerprinting"
    executor: SecureCommandExecutor = Field(..., description="Command executor instance")

    def _run(self, target: str, scan_type: str = "basic") -> str:
        """Execute Nmap scan based on scan type"""

        scan_commands = {
            "basic": f"sudo nmap -sV -sC -O {target}",
            "full": f"sudo nmap -sV -sC -O -p- {target}",
            "stealth": f"sudo nmap -sS -sV -O {target}",
            "udp": f"sudo nmap -sU --top-ports 1000 {target}",
            "vuln": f"sudo nmap --script vuln {target}",
            "fast": f"sudo nmap -F -sV {target}"
        }

        command = scan_commands.get(scan_type, scan_commands["basic"])
        result = self.executor.execute_command(command)

        if result.success:
            # Parse and analyze Nmap output
            analysis = self._analyze_nmap_output(result.stdout)
            return f"Nmap scan completed successfully.\n\nCommand: {command}\n\nResults:\n{result.stdout}\n\nAnalysis:\n{analysis}"
        else:
            return f"Nmap scan failed. Command: {command}\nError: {result.stderr}"

    def _analyze_nmap_output(self, output: str) -> str:
        """Analyze Nmap output and provide insights"""
        analysis = []

        lines = output.split('\n')
        open_ports = []
        services = []

        for line in lines:
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
            elif "Service detection performed" in line:
                services.append(line.strip())

        if open_ports:
            analysis.append(f"Found {len(open_ports)} open ports:")
            analysis.extend([f"  - {port}" for port in open_ports[:10]])  # Show first 10
            if len(open_ports) > 10:
                analysis.append(f"  ... and {len(open_ports) - 10} more ports")

        # Security recommendations
        if any("22/tcp" in port for port in open_ports):
            analysis.append("\n🔒 SSH service detected - ensure strong authentication")
        if any("80/tcp" in port or "443/tcp" in port for port in open_ports):
            analysis.append("🌐 Web services detected - recommend web application testing")
        if any("21/tcp" in port for port in open_ports):
            analysis.append("⚠️  FTP service detected - check for anonymous access")

        return "\n".join(analysis) if analysis else "No significant findings in port scan"

class SubdomainEnumerationTool(BaseTool):
    """Subdomain enumeration using multiple tools"""
    name: str = "subdomain_enumerator"
    description: str = "Discover subdomains using Sublist3r, Subfinder, Amass, and other tools"
    executor: SecureCommandExecutor = Field(..., description="Command executor instance")

    def _run(self, domain: str, tool: str = "sublist3r") -> str:
        """Execute subdomain enumeration"""

        commands = {
            "sublist3r": f"sublist3r -d {domain} -o {domain}_sublist3r.txt",
            "subfinder": f"subfinder -d {domain} -o {domain}_subfinder.txt",
            "amass": f"amass enum -d {domain} -o {domain}_amass.txt",
            "assetfinder": f"echo {domain} | assetfinder --subs-only",
        }

        if tool == "all":
            # Run all available tools
            results = []
            all_subdomains = set()

            for tool_name, command in commands.items():
                result = self.executor.execute_command(command)
                if result.success:
                    results.append(f"✅ {tool_name}: Success")
                    # Extract subdomains from stdout
                    if tool_name == "assetfinder":
                        tool_subdomains = set(line.strip() for line in result.stdout.split('\n') if line.strip())
                        all_subdomains.update(tool_subdomains)
                else:
                    results.append(f"❌ {tool_name}: {result.stderr}")

            # Save consolidated results
            if all_subdomains:
                consolidated_file = f"{domain}_all_subdomains.txt"
                consolidated_path = os.path.join(self.executor.config.output_dir, consolidated_file)
                with open(consolidated_path, 'w') as f:
                    for subdomain in sorted(all_subdomains):
                        f.write(f"{subdomain}\n")

                analysis = self._analyze_subdomains(list(all_subdomains))
                return f"Subdomain enumeration completed.\n\nTools executed: {len(commands)}\nUnique subdomains found: {len(all_subdomains)}\n\nResults saved to: {consolidated_file}\n\nAnalysis:\n{analysis}"
            else:
                return "Subdomain enumeration completed but no subdomains found."

        else:
            command = commands.get(tool, commands["sublist3r"])
            result = self.executor.execute_command(command)

            if result.success:
                analysis = self._analyze_subdomains(result.stdout.split('\n'))
                return f"Subdomain enumeration with {tool} completed.\n\nCommand: {command}\n\nResults:\n{result.stdout}\n\nAnalysis:\n{analysis}"
            else:
                return f"Subdomain enumeration failed. Command: {command}\nError: {result.stderr}"

    def _analyze_subdomains(self, subdomains: List[str]) -> str:
        """Analyze discovered subdomains"""
        analysis = []

        # Filter and categorize subdomains
        valid_subdomains = [s.strip() for s in subdomains if s.strip() and '.' in s]

        if not valid_subdomains:
            return "No valid subdomains found for analysis"

        # Categorize by common patterns
        categories = {
            'admin': [s for s in valid_subdomains if any(pattern in s.lower() for pattern in ['admin', 'manage', 'control'])],
            'dev': [s for s in valid_subdomains if any(pattern in s.lower() for pattern in ['dev', 'test', 'staging', 'beta'])],
            'api': [s for s in valid_subdomains if any(pattern in s.lower() for pattern in ['api', 'rest', 'graphql'])],
            'mail': [s for s in valid_subdomains if any(pattern in s.lower() for pattern in ['mail', 'smtp', 'imap'])],
            'ftp': [s for s in valid_subdomains if any(pattern in s.lower() for pattern in ['ftp', 'files', 'download'])],
        }

        analysis.append(f"Total subdomains analyzed: {len(valid_subdomains)}")

        for category, domains in categories.items():
            if domains:
                analysis.append(f"\n{category.upper()} related ({len(domains)}):")
                for domain in domains[:5]:  # Show first 5
                    analysis.append(f"  - {domain}")
                if len(domains) > 5:
                    analysis.append(f"  ... and {len(domains) - 5} more")

        # Security recommendations
        if categories['admin']:
            analysis.append("\n🚨 Admin interfaces found - high priority for testing")
        if categories['dev']:
            analysis.append("🔧 Development environments found - may have weaker security")
        if categories['api']:
            analysis.append("🔌 API endpoints found - test for authentication bypass")

        return "\n".join(analysis)

class OSINTTool(BaseTool):
    """OSINT collection using local tools"""
    name: str = "osint_collector"
    description: str = "Collect OSINT data using whois, dig, theHarvester, and other local tools"
    executor: SecureCommandExecutor = Field(..., description="Command executor instance")

    def _run(self, target: str, info_type: str = "all") -> str:
        """Collect OSINT information"""

        results = {}

        if info_type in ["all", "whois"]:
            whois_result = self.executor.execute_command(f"whois {target}")
            results["whois"] = whois_result

        if info_type in ["all", "dns"]:
            dns_commands = [
                f"dig {target} ANY",
                f"dig {target} MX", 
                f"dig {target} NS",
                f"dig {target} TXT"
            ]
            results["dns"] = []
            for cmd in dns_commands:
                dns_result = self.executor.execute_command(cmd)
                results["dns"].append(dns_result)

        if info_type in ["all", "harvester"]:
            # Try theHarvester with different sources
            harvester_result = self.executor.execute_command(f"theharvester -d {target} -l 100 -b google")
            results["harvester"] = harvester_result

        # Compile results
        analysis = self._analyze_osint_results(results, target)

        return f"OSINT collection completed for {target}\n\nAnalysis:\n{analysis}"

    def _analyze_osint_results(self, results: Dict, target: str) -> str:
        """Analyze OSINT results"""
        analysis = []

        # Analyze WHOIS data
        if "whois" in results and results["whois"].success:
            whois_data = results["whois"].stdout

            # Extract key information
            if "Creation Date" in whois_data or "created:" in whois_data.lower():
                analysis.append("📅 Domain registration information available")

            if "admin" in whois_data.lower() or "tech" in whois_data.lower():
                analysis.append("👤 Contact information found in WHOIS")

            if "nameserver" in whois_data.lower() or "nserver" in whois_data.lower():
                analysis.append("🌐 Name server information available")

        # Analyze DNS data
        if "dns" in results:
            mx_records = any("MX" in str(result.stdout) for result in results["dns"] if result.success)
            txt_records = any("TXT" in str(result.stdout) for result in results["dns"] if result.success)

            if mx_records:
                analysis.append("📧 Mail exchange records found")
            if txt_records:
                analysis.append("📝 TXT records found - may contain SPF/DKIM info")

        # Analyze theHarvester results
        if "harvester" in results and results["harvester"].success:
            harvester_output = results["harvester"].stdout
            if "@" in harvester_output:
                email_count = harvester_output.count("@")
                analysis.append(f"📧 Found approximately {email_count} email addresses")

            if "linkedin" in harvester_output.lower():
                analysis.append("💼 LinkedIn profiles discovered")

        return "\n".join(analysis) if analysis else "OSINT collection completed with minimal findings"

class VulnerabilityScanner(BaseTool):
    """Vulnerability scanning using Nuclei and other tools"""
    name: str = "vulnerability_scanner"
    description: str = "Scan for vulnerabilities using Nuclei, Nikto, and custom scripts"
    executor: SecureCommandExecutor = Field(..., description="Command executor instance")

    def _run(self, target: str, scan_type: str = "web") -> str:
        """Execute vulnerability scans"""

        results = []

        if scan_type in ["all", "web"]:
            # Web application vulnerability scanning
            web_commands = [
                f"nuclei -u {target} -severity critical,high,medium",
                f"nikto -h {target}",
                f"whatweb {target}"
            ]

            for cmd in web_commands:
                result = self.executor.execute_command(cmd)
                tool_name = cmd.split()[0]
                if result.success:
                    results.append(f"✅ {tool_name}: Scan completed")
                    if result.stdout.strip():
                        results.append(f"Findings: {len(result.stdout.splitlines()) - 1} lines of output")

                else:
                    results.append(f"❌ {tool_name}: {result.stderr}")

        if scan_type in ["all", "ssl"]:
            # SSL/TLS testing
            ssl_result = self.executor.execute_command(f"nmap --script ssl-enum-ciphers -p 443 {target}")
            if ssl_result.success:
                results.append("🔐 SSL/TLS configuration analyzed")
            else:
                results.append(f"❌ SSL scan failed: {ssl_result.stderr}")

        analysis = "\n".join(results)
        recommendations = self._generate_security_recommendations(results)

        return f"Vulnerability scanning completed for {target}\n\nResults:\n{analysis}\n\nRecommendations:\n{recommendations}"

    def _generate_security_recommendations(self, results: List[str]) -> str:
        """Generate security recommendations based on scan results"""
        recommendations = []

        if any("nuclei" in result for result in results):
            recommendations.append("🔍 Review Nuclei findings for known vulnerabilities")

        if any("nikto" in result for result in results):
            recommendations.append("🌐 Check Nikto results for web server misconfigurations")

        if any("SSL" in result for result in results):
            recommendations.append("🔐 Verify SSL/TLS configuration meets security standards")

        recommendations.extend([
            "📊 Prioritize critical and high-severity findings",
            "🔄 Implement regular vulnerability scanning schedule",
            "📋 Document all findings for remediation tracking"
        ])

        return "\n".join(recommendations)

# Enhanced Local Reconnaissance System
class LocalAgenticReconSystem:
    """
    Advanced local tool-based reconnaissance system using CrewAI
    """

    def __init__(self, config: LocalReconConfig):
        self.config = config
        self.results = {}

        # Ensure output directory exists
        os.makedirs(config.output_dir, exist_ok=True)

        # Initialize command executor FIRST
        self.executor = SecureCommandExecutor(config)

        # Initialize LLM (can work with local LLMs too)
        try:

                from langchain_community.chat_models import ChatOllama

                self.llm = ChatOllama(
                    model="ollama/llama3.1:8b",
                    base_url="http://164.90.147.109:11434",  # your Ollama server
                    temperature=0
                    # provider="ollama"
                )

        except Exception as e:
            print(f"❌ Failed to initialize LLM: {e}")
            print("💡 Please install Ollama or set OPENAI_API_KEY environment variable")
            raise

        # Initialize tools with executor
        self.tools = self._initialize_tools()

    def _initialize_tools(self) -> Dict[str, BaseTool]:
        """Initialize all reconnaissance tools"""
        try:
            return {
                'nmap': NmapTool(executor=self.executor),
                'subdomain': SubdomainEnumerationTool(executor=self.executor),
                'osint': OSINTTool(executor=self.executor),
                'vuln': VulnerabilityScanner(executor=self.executor)
            }
        except Exception as e:
            print(f"❌ Error initializing tools: {e}")
            raise

    def create_agents(self) -> Dict[str, Agent]:
        """Create specialized reconnaissance agents"""

        # Network Reconnaissance Agent
        network_agent = Agent(
            role="Network Reconnaissance Specialist",
            goal=f"Perform comprehensive network reconnaissance on {self.config.target_domain} using local tools",
            backstory="""You are an expert network reconnaissance specialist with deep knowledge of 
            network protocols, port scanning, and service identification. You use tools like Nmap 
            to discover open ports, running services, and potential attack vectors. You analyze 
            results systematically and provide actionable intelligence.""",
            tools=[self.tools['nmap']],
            llm=self.llm,
            verbose=True
        )

        # Subdomain Discovery Agent  
        subdomain_agent = Agent(
            role="Subdomain Discovery Expert",
            goal=f"Discover all possible subdomains for {self.config.target_domain} using multiple enumeration techniques",
            backstory="""You are a subdomain enumeration specialist who excels at discovering 
            hidden and obscure subdomains. You use multiple tools and techniques to ensure 
            comprehensive coverage and can analyze subdomain patterns to identify high-value targets.""",
            tools=[self.tools['subdomain']],
            llm=self.llm,
            verbose=True
        )

        # OSINT Collection Agent
        osint_agent = Agent(
            role="OSINT Intelligence Analyst", 
            goal=f"Gather comprehensive open-source intelligence about {self.config.target_domain}",
            backstory="""You are an OSINT specialist who excels at gathering intelligence from 
            publicly available sources. You use tools like WHOIS, DNS enumeration, and theHarvester 
            to build a comprehensive profile of the target organization.""",
            tools=[self.tools['osint']],
            llm=self.llm,
            verbose=True
        )

        # Vulnerability Assessment Agent
        vulnerability_agent = Agent(
            role="Vulnerability Assessment Specialist",
            goal=f"Identify security vulnerabilities and misconfigurations in {self.config.target_domain}",
            backstory="""You are a vulnerability assessment expert who specializes in identifying 
            security weaknesses using automated tools. You use Nuclei, Nikto, and other scanners 
            to find known vulnerabilities and provide risk-based prioritization.""",
            tools=[self.tools['vuln']],
            llm=self.llm,
            verbose=True
        )

        # Analysis and Reporting Agent
        report_agent = Agent(
            role="Security Analysis and Reporting Specialist",
            goal="Analyze all reconnaissance findings and create comprehensive security reports",
            backstory="""You are a senior security analyst who specializes in synthesizing 
            technical reconnaissance data into actionable security intelligence. You create 
            detailed reports with risk assessments, attack vectors, and remediation recommendations.""",
            llm=self.llm,
            verbose=True
        )

        return {
            'network': network_agent,
            'subdomain': subdomain_agent, 
            'osint': osint_agent,
            'vulnerability': vulnerability_agent,
            'report': report_agent
        }

    def create_tasks(self, agents: Dict[str, Agent]) -> List[Task]:
        """Create reconnaissance tasks"""

        # Network Reconnaissance Task
        network_task = Task(
            description=f"""
            Perform comprehensive network reconnaissance on {self.config.target_domain}:

            1. Conduct a basic port scan to identify open services
            2. Perform service version detection and OS fingerprinting  
            3. Execute vulnerability-specific Nmap scripts if appropriate
            4. Analyze results for potential security issues
            5. Identify high-priority targets for further investigation

            Start with a basic scan, then decide if additional scans are needed based on findings.
            Focus on identifying critical services and potential entry points.
            """,
            agent=agents['network'],
            expected_output="Detailed network reconnaissance report with open ports, services, and security analysis"
        )

        # Subdomain Discovery Task
        subdomain_task = Task(
            description=f"""
            Discover subdomains for {self.config.target_domain} using comprehensive enumeration:

            1. Start with sublist3r for initial discovery
            2. Use additional tools if initial results are promising
            3. Consolidate results and remove duplicates
            4. Categorize subdomains by function (admin, dev, api, etc.)
            5. Identify high-value targets for security testing

            Focus on finding subdomains that might have security implications.
            """,
            agent=agents['subdomain'],
            expected_output="Comprehensive subdomain enumeration report with categorized results"
        )

        # OSINT Collection Task
        osint_task = Task(
            description=f"""
            Gather OSINT intelligence on {self.config.target_domain}:

            1. Collect WHOIS information for domain registration details
            2. Perform DNS enumeration for infrastructure mapping
            3. Try theHarvester for additional intelligence if appropriate
            4. Analyze DNS records for security configurations
            5. Identify organizational structure and key information

            Focus on gathering actionable intelligence that supports security assessment.
            Ensure all collection follows ethical guidelines.
            """,
            agent=agents['osint'],
            expected_output="OSINT intelligence report with organizational and technical details"
        )

        # Vulnerability Assessment Task
        vulnerability_task = Task(
            description=f"""
            Perform vulnerability assessment on {self.config.target_domain}:

            1. Execute Nuclei scans for known vulnerabilities
            2. Use additional web application security tools as appropriate
            3. Analyze SSL/TLS configuration if web services are found
            4. Test for common web application vulnerabilities
            5. Prioritize findings by risk level and exploitability

            Focus on identifying the most critical security issues.
            Provide risk-based prioritization for remediation.
            """,
            agent=agents['vulnerability'],
            expected_output="Vulnerability assessment report with risk-prioritized findings",
            context=[network_task, subdomain_task]
        )

        # Comprehensive Reporting Task
        report_task = Task(
            description=f"""
            Create comprehensive security reconnaissance report for {self.config.target_domain}:

            1. Synthesize all reconnaissance findings into unified intelligence
            2. Analyze attack surface and potential entry points
            3. Create risk-based prioritization of security issues
            4. Develop attack scenarios and potential impact assessments
            5. Provide detailed remediation recommendations
            6. Include executive summary for stakeholder communication

            Create a professional report that is actionable for both technical and executive audiences.
            """,
            agent=agents['report'], 
            expected_output="Professional security reconnaissance report with executive summary and technical details",
            context=[network_task, subdomain_task, osint_task, vulnerability_task]
        )

        return [network_task, subdomain_task, osint_task, vulnerability_task, report_task]

    def run_reconnaissance(self) -> str:
        """Execute the full reconnaissance workflow"""

        print(f"🚀 Starting Local Agentic Reconnaissance System")
        print(f"📍 Target: {self.config.target_domain}")
        print(f"💾 Output Directory: {self.config.output_dir}")
        print(f"⚡ Max Threads: {self.config.max_threads}")
        print(f"⏱️  Timeout: {self.config.timeout}s")
        print("=" * 80)

        # Verify tool availability
        self._verify_tools()

        # Create agents and tasks
        agents = self.create_agents()
        tasks = self.create_tasks(agents)

        # Create and execute crew
        crew = Crew(
            agents=list(agents.values()),
            tasks=tasks,
            process=Process.sequential,
            verbose=True
        )

        # Execute reconnaissance
        print("🔍 Executing reconnaissance workflow...")
        start_time = time.time()

        try:
            result = crew.kickoff()
            execution_time = time.time() - start_time

            print(f"✅ Reconnaissance completed in {execution_time:.2f} seconds")

            # Save results
            self._save_results(result, execution_time)

            return str(result)

        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"❌ Reconnaissance failed after {execution_time:.2f} seconds: {str(e)}"
            print(error_msg)
            print(f"📋 Check that all required tools are installed and accessible")
            return error_msg

    def _verify_tools(self):
        """Verify that required tools are installed"""
        required_tools = [
            'nmap', 'whois', 'dig'
        ]

        optional_tools = [
            'sublist3r', 'subfinder', 'nuclei', 'nikto', 'theharvester'
        ]

        print("🔧 Verifying tool availability...")

        missing_required = []
        missing_optional = []

        for tool in required_tools:
            result = self.executor.execute_command(f"which {tool}", target_validation=False)
            if not result.success:
                missing_required.append(tool)
            else:
                print(f"  ✅ {tool}: Available")

        for tool in optional_tools:
            result = self.executor.execute_command(f"which {tool}", target_validation=False)
            if not result.success:
                missing_optional.append(tool)
            else:
                print(f"  ✅ {tool}: Available")

        if missing_required:
            print(f"  ❌ Missing REQUIRED tools: {', '.join(missing_required)}")
            print("  🚨 Install missing required tools before proceeding")

        if missing_optional:
            print(f"  ⚠️  Missing optional tools: {', '.join(missing_optional)}")
            print("  💡 Some reconnaissance features may be limited")

        if not missing_required:
            print("  🎉 All required tools are available!")

        print()

    def _save_results(self, result: str, execution_time: float):
        """Save reconnaissance results"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save main report
        report_file = f"reconnaissance_report_{self.config.target_domain}_{timestamp}.txt"
        report_path = os.path.join(self.config.output_dir, report_file)

        with open(report_path, 'w') as f:
            f.write(f"# Local Agentic Reconnaissance Report\n")
            f.write(f"Target: {self.config.target_domain}\n")
            f.write(f"Execution Time: {execution_time:.2f} seconds\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write("=" * 80 + "\n\n")
            f.write(str(result))

        # Save metadata
        metadata = {
            "target": self.config.target_domain,
            "timestamp": timestamp,
            "execution_time": execution_time,
            "output_dir": self.config.output_dir,
            "config": {
                "max_threads": self.config.max_threads,
                "timeout": self.config.timeout,
                "ethical_mode": self.config.ethical_mode
            }
        }

        metadata_file = f"metadata_{self.config.target_domain}_{timestamp}.json"
        metadata_path = os.path.join(self.config.output_dir, metadata_file)

        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2, default=str)

        print(f"💾 Results saved:")
        print(f"  📄 Report: {report_path}")
        print(f"  📊 Metadata: {metadata_path}")

# Usage example and main function
def main():
    """
    Main function demonstrating the local agentic reconnaissance system
    """

    print("=" * 80)
    print("🤖 LOCAL AGENTIC RECONNAISSANCE SYSTEM v2.1 - CORRECTED")
    print("=" * 80)
    print()
    print("⚖️  LEGAL DISCLAIMER:")
    print("This tool is for authorized security testing only.")
    print("Always obtain written permission before testing any target.")
    print("Use only on systems you own or have explicit authorization to test.")
    print("Follow responsible disclosure practices.")
    print("=" * 80)
    print()

    # Get target from user
    target = input("🎯 Enter target domain (e.g., hash13.com): ").strip()

    if not target:
        print("❌ No target specified. Exiting.")
        return

    # Confirm authorization
    authorization = input(f"⚖️  Do you have written authorization to test {target}? (yes/no): ").strip().lower()

    if authorization != 'yes':
        print("❌ Authorization not confirmed. Exiting for legal compliance.")
        return

    # Configuration
    config = LocalReconConfig(
        target_domain=target,
        output_dir=f"./recon_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        max_threads=5,
        timeout=300,
        verbose=True,
        ethical_mode=True
    )

    # Initialize and run system
    try:
        recon_system = LocalAgenticReconSystem(config)
        result = recon_system.run_reconnaissance()

        print("\n" + "=" * 80)
        print("🎉 RECONNAISSANCE COMPLETED!")
        print("=" * 80)

        return result

    except KeyboardInterrupt:
        print("\n⏹️  Reconnaissance interrupted by user")
        return None
    except Exception as e:
        print(f"\n❌ Error during reconnaissance: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    result = main()
