

# Security Automation with Ansible 2


- Use Ansible playbooks, roles, modules, and templating to build generic, testable playbooks
- Manage Linux and Windows hosts remotely in a repeatable and predictable manner
- See how to perform security patch management, and security hardening with scheduling and automation
- Set up AWS Lambda for a serverless automated defense
- Run continuous security scans against your hosts and automatically fix and harden the gaps
- Extend Ansible to write your custom modules and use them as part of your already existing security automation programs
- Perform automation security audit checks for applications using Ansible
- Manage secrets in Ansible using Ansible Vault


```


Introduction to Ansible Playbooks and Roles

            Ansible terms to keep in mind 
            Playbooks
            Ansible modules
            YAML syntax for writing Ansible playbooks
            Ansible roles
            Templates with Jinja2
                    Jinja templating examples
                        Conditional example
                        Loops example
            LAMP stack playbook example – combining all the concepts


Ansible Tower, Jenkins, and Other Automation Tools

            Scheduling tools to enable the next abstraction of automation
            Getting up and running
                    Setting up Ansible Tower
                    Setting up Jenkins
                    Setting up Rundeck
            Security automation use cases
                    Adding playbooks
                    Ansible Tower configuration
                    Jenkins Ansible integration configuration
                    Rundeck configuration
            Authentication and  data security
                    RBAC for Ansible Tower
                    TLS/SSL for Ansible Tower
                    Encryption and data security for Ansible Tower
                    RBAC for Jenkins
                    TLS/SSL for Jenkins
                    Encryption and data security for Jenkins
                    RBAC for Rundeck
                    HTTP/TLS for Rundeck
                    Encryption and data security for Rundeck

            Output of the playbooks
                    Report management for Ansible Tower
                    Report management for Jenkins 
                    Report management for Rundeck
            Scheduling of jobs
            Alerting, notifications, and webhooks

Setting Up a Hardened WordPress with Encrypted Automated Backups
            CLI for WordPress
            Why Ansible for this setup?
                    A complete WordPress installation step-by-step
                            Setting up nginx web server
                            Setting up prerequisites
                            Setting up MySQL database
                            Installing PHP for WordPress setup
                            Installing WordPress using WP-CLI
                            Hardening SSH service
                            Hardening a database service
                            Hardening nginx 
                            Hardening WordPress
                            Hardening a host firewall service
                            Setting up automated encrypted backups in AWS S3
                            Executing playbook against an Ubuntu 16.04 server using Ansible Tower
            Secure automated the WordPress updates
                        Scheduling via Ansible Tower for daily updates
            Setting up Apache2 web server
            Enabling TLS/SSL with Let's Encrypt
            What if you don't want to roll your own? The Trellis stack
                    Why would we use Trellis, and when is it a good idea to use it?
            WordPress on Windows 
                    How to enable WinRM in Windows
                            Running Ansible against a Windows server
                            Installing IIS server using playbook


Log Monitoring and Serverless Automated Defense (Elastic Stack in AWS)

            Introduction to Elastic Stack
                    Elasticsearch
                    Logstash
                    Kibana
                    Beats
                    Why should we use Elastic Stack for security monitoring and alerting?
                    Prerequisites for setting up Elastic Stack
                    Setting up the Elastic Stack
                            Logstash integrations
                            Kibana
                            ElastAlert
                    Installing Elasticsearch
                    Installing Logstash
                    Logstash configuration
                    Installing Kibana
                    Setting up nginx reverse proxy
                    Installing Beats to send logs to Elastic Stack
                    ElastAlert for alerting
                    Configuring the Let's Encrypt service
                    ElastAlert rule configuration
                    Kibana dashboards
            Automated defense?
                    AWS services used in setup
                            DynamoDB
                            Blacklist lambda function
                            HandleExpiry lambda function
                            Cloudwatch
                            VPC Network ACL
                    Setup
                    Configuration
                    Usage - block an IP address
                            Request
                            Response
                    Automated defense lambda in action


Automating Web Application Security Testing Using OWASP ZAP

            Installing OWASP ZAP
            Installing Docker runtime
            OWASP ZAP Docker container setup
                    A specialized tool for working with Containers - Ansible Container 
            Configuring ZAP Baseline scan
                    Running a vulnerable application container
                    Running an OWASP ZAP Baseline scan
            Security testing against web applications and websites
                    Running ZAP full scan against DVWS
                    Testing web APIs
            Continuous scanning workflow using ZAP and Jenkins
                    Setting up Jenkins
                        Setting up the OWASP ZAP Jenkins plugin
                        Some assembly required
            Triggering the build (ZAP scan)
                    Playbook to do this with automation
            ZAP Docker and Jenkins


Vulnerability Scanning with Nessus

            Introduction to Nessus
            Installing Nessus for vulnerability assessments
            Configuring Nessus for vulnerability scanning
            Executing scans against a network
                    Basic network scanning
            Running a scan using AutoNessus
                    Setting up AutoNessus
                    Running scans using AutoNessus
                        Listing current available scans and IDs
                        Starting a specified scan using scan ID
            Storing results
            Installing the Nessus REST API Python client
                    Downloading reports using the Nessus REST API
            Nessus configuration


Security Hardening for Applications and Networks

            Security hardening with benchmarks such as CIS, STIGs, and NIST
            Operating system hardening for baseline using an Ansible playbook
            STIGs Ansible role for automated security hardening for Linux hosts
            Continuous security scans and reports for OpenSCAP using Ansible Tower
            CIS Benchmarks
                    Ubuntu CIS Benchmarks (server level)
                    AWS benchmarks (cloud provider level)
            Lynis – open source security auditing tool for Unix/Linux systems
                    Lynis commands and advanced options
            Windows server audit using Ansible playbooks
                    Windows security updates playbook
                    Windows workstation and server audit
            Automating security audit checks for networking devices using Ansible
                    Nmap scanning and NSE
                        Nmap NSE scanning playbook
                    AWS security audit using Scout2

            Automation security audit checks for applications using Ansible
                    Source code analysis scanners
                        Brakeman scanner – Rails security scanner
                    Dependency-checking scanners
                        OWASP Dependency-Check
                    Running web application security scanners
                        Nikto – web server scanner
                    Framework-specific security scanners
                        WordPress vulnerability scanner – WPScan
            Automated patching approaches using Ansible
                    Rolling updates
                    BlueGreen deployments
                        BlueGreen deployment setup playbook
                        BlueGreen deployment update playbook


Continuous Security Scanning for Docker Containers

            Understanding continuous security concepts
            Automating vulnerability assessments of Docker containers using Ansible
            Docker Bench for Security
            Clair
            Scheduled scans using Ansible Tower for Docker security
            Anchore – open container compliance platform 
            Anchore Engine service setup
            Anchore CLI scanner
            Scheduled scans using Ansible Tower for operating systems and kernel security
            Vuls – vulnerability scanner
            Vuls setup playbook
            Vuls scanning playbook
            Scheduled scans for file integrity checks, host-level monitoring using Ansible for various compliance initiatives
            osquery



Automating Lab Setups for Forensics Collection and Malware Analysis

                Creating Ansible playbooks for labs for isolated environments
                Collecting file and domain malware identification and classification
                VirusTotal  API tool set up
                VirusTotal API scan for malware samples
                Setting up the Cuckoo Sandbox environment
                Setting up the Cuckoo host
                Setting up Cuckoo guest
                Submitting samples and reporting using Ansible playbook 
                Setting up Cuckoo using Docker containers
                Setting up MISP and Threat Sharing
                Setting up MISP using Ansible playbook
                MISP web user interface
                Setting up Viper - binary management and analysis framework
                Creating Ansible playbooks for collection and storage with secure backup of forensic artifacts
                Collecting log artifacts for incident response
                Secure backups for data collection


Writing an Ansible Module for Security Testing

                Getting started with a hello world Ansible module
                Code
                Setting up the development environment
                Planning and what to keep in mind
                OWASP ZAP module
                Create ZAP using Docker
                Creating a vulnerable application
                Ansible module template
                Metadata
                Documenting the module
                Source code template 
                OWASP ZAP Python API sample script
                Complete code listing
                Running the module
                Playbook for the module
                Adding an API key as an argument
                Adding scan type as an argument
                Using Ansible as a Python module 


Ansible Security Best Practices, References, and Further Reading

                Working with Ansible Vault
                How to use Ansible Vault with variables and files
                Ansible Vault single encrypted variable
                Ansible Vault usage in Ansible Tower
                Setting up and using Ansible Galaxy 
                Using Ansible Galaxy roles
                Publishing our role to Ansible Galaxy
                Ansible Galaxy local setup
                Ansible controller machine security
                Explanation of Ansible OS hardening playbook
                Best practices and reference playbook projects
                DebOps – your Debian-based data center in a box
                Setting up the DebOps controller
                Algo – set up a personal IPSEC VPN in the cloud
                OpenStack-Ansible
                Additional references
                Streisand – automated installation and configuration of anti-censorship software
                Sovereign – maintain your own private cloud using Ansible playbooks
                AWX – open source version of Ansible Tower