from assemblyline_v4_service.common.result import ResultSection, ResultTableSection, TableRow, ResultKeyValueSection, ResultURLSection
from assemblyline.odm.models.ontology.results import sandbox, network, process
import urllib.parse

class ResultProcessor:
    def __init__(self, service):
        self.service = service
        self.log = service.log

    def create_main_section(self, overview):
        """Create the main result section with all subsections"""
        self.log.info("Creating result sections from analysis data")
        main_section = ResultSection("Hybrid Analysis Results")
        
        self._add_summary_section(overview, main_section)
        self._add_submission_history(overview, main_section)
        self._add_file_info_section(overview, main_section)
        self._add_scanner_results(overview, main_section)
        self._add_mitre_attack_section(overview, main_section)
        self._add_signature_stats_section(overview, main_section)
        self._add_behavior_section(overview, main_section)
        self._add_crowdstrike_analysis(overview, main_section)
        self._add_process_section(overview, main_section)
        self._add_network_section(overview, main_section)
        
        self._map_ontologies(overview)
        
        return main_section

    def _get_objectid(self, tag, prefix=""):
        return {
            "tag": tag,
            "ontology_id": f"{prefix}{tag}",
            "service_name": self.service.name if hasattr(self.service, 'name') else "hybridanalysis"
        }

    def _map_ontologies(self, overview):
        try:
            analysis_start = overview.get('analysis_start_time', '1970-01-01T00:00:00.000000Z')
            
            # Sandbox Ontology
            sb = sandbox.Sandbox({
                "objectid": self._get_objectid("HybridAnalysis", "sandbox_"),
                "analysis_metadata": {
                    "start_time": analysis_start
                },
                "sandbox_name": "Hybrid Analysis"
            })
            self.service.ontology.add_result_part(sandbox.Sandbox, sb.as_primitives())

            # Network Ontology
            for domain in overview.get('domains', []):
                nc = network.NetworkConnection({
                    "objectid": self._get_objectid(domain, "network_domain_"),
                    "connection_type": "dns",
                    "dns_details": {
                        "domain": domain,
                        "lookup_type": "A"
                    }
                })
                self.service.ontology.add_result_part(network.NetworkConnection, nc.as_primitives())
            
            for host in overview.get('hosts', []):
                nc = network.NetworkConnection({
                    "objectid": self._get_objectid(host, "network_ip_"),
                    "destination_ip": host
                })
                self.service.ontology.add_result_part(network.NetworkConnection, nc.as_primitives())

            # Process Ontology
            for proc in overview.get('processes', []):
                if proc.get('name'):
                    p = process.Process({
                        "objectid": self._get_objectid(proc.get('name'), f"process_{proc.get('pid', '0')}_"),
                        "image": proc.get('name'),
                        "pid": proc.get('pid'),
                        "command_line": proc.get('command_line'),
                        "start_time": analysis_start
                    })
                    self.service.ontology.add_result_part(process.Process, p.as_primitives())

        except Exception as e:
            self.log.warning(f"Failed to map ontologies: {str(e)}")

    def _add_summary_section(self, overview, main_section):
        """Add summary section with verdict and threat information"""
        summary_section = ResultKeyValueSection("Analysis Summary")
        
        verdict = overview.get('verdict', 'Unknown')
        summary_section.set_item("Verdict", verdict)
        if verdict.lower() == 'malicious':
            summary_section.set_heuristic(9)
        
        threat_score = overview.get('threat_score')
        if threat_score is not None:
            threat_sec = ResultKeyValueSection("Threat Score")
            threat_sec.set_item("Score", threat_score)
            if threat_score >= 85:
                self.log.info(f"Critical threat score detected: {threat_score}")
                threat_sec.set_heuristic(1)
            elif threat_score >= 70:
                self.log.info(f"High threat score detected: {threat_score}")
                threat_sec.set_heuristic(2)
            summary_section.add_subsection(threat_sec)
        
        av_detect = overview.get('av_detect')
        if av_detect is not None:
            av_sec = ResultKeyValueSection("AV Detection")
            av_sec.set_item("Detection Rate", av_detect)
            if av_detect > 30:
                self.log.info(f"High AV detection rate: {av_detect}")
                av_sec.set_heuristic(3)
            summary_section.add_subsection(av_sec)
        
        if overview.get('vx_family'):
            fam_sec = ResultKeyValueSection("Malware Family")
            fam_sec.set_item("Family", overview['vx_family'])
            fam_sec.add_tag('attribution.family', overview['vx_family'])
            fam_sec.set_heuristic(8)
            summary_section.add_subsection(fam_sec)
            
        if overview.get('environment_description'):
            summary_section.set_item("Analysis Environment", overview['environment_description'])
            
        main_section.add_subsection(summary_section)
        
        # Add link to HybridAnalysis
        if overview.get('sha256'):
            report_url = f"https://www.hybrid-analysis.com/sample/{overview['sha256']}"
            url_section = ResultURLSection("Hybrid Analysis Report Link")
            url_section.add_url(report_url, name="Click to open the full analysis report in Hybrid Analysis")
            main_section.add_subsection(url_section)

    def _add_submission_history(self, overview, main_section):
        """Add submission history section"""
        if overview.get('submissions'):
            history_section = ResultTableSection("Submission History", auto_collapse=True)
            history_section.set_column_order([
                "filename",
                "submission_id",
                "submitted_at",
                "source_url"
            ])
            
            for submission in overview['submissions']:
                row = TableRow({
                    "filename": submission.get('filename', ''),
                    "submission_id": submission.get('submission_id', ''),
                    "submitted_at": submission.get('created_at', ''),
                    "source_url": submission.get('url', 'N/A')
                })
                history_section.add_row(row)
                
                if submission.get('url'):
                    history_section.add_tag('network.static.uri', submission['url'])
                    
            main_section.add_subsection(history_section)

    def _add_file_info_section(self, overview, main_section):
        """Add detailed file information section"""
        file_info = ResultKeyValueSection("File Information", auto_collapse=True)
        
        if overview.get('type'):
            file_info.set_item("File Type", overview['type'])
        if overview.get('size'):
            file_info.set_item("File Size (bytes)", overview['size'])
            
        if overview.get('md5'):
            file_info.set_item("MD5", overview['md5'])
            file_info.add_tag('file.md5', overview['md5'])
        if overview.get('sha1'):
            file_info.set_item("SHA1", overview['sha1'])
            file_info.add_tag('file.sha1', overview['sha1'])
        if overview.get('sha256'):
            file_info.set_item("SHA256", overview['sha256'])
            file_info.add_tag('file.sha256', overview['sha256'])
                
        if overview.get('type_short') and 'peexe' in overview['type_short']:
            pe_info = ResultKeyValueSection("PE Information")
            if overview.get('imphash'):
                pe_info.set_item("Import Hash", overview['imphash'])
            if overview.get('entrypoint'):
                pe_info.set_item("Entry Point", overview['entrypoint'])
            if overview.get('image_base'):
                pe_info.set_item("Image Base", overview['image_base'])
            if overview.get('subsystem'):
                pe_info.set_item("Subsystem", overview['subsystem'])
            
            if pe_info.body:
                file_info.add_subsection(pe_info)
                
        main_section.add_subsection(file_info)

    def _add_scanner_results(self, overview, main_section):
        """Add scanner results section"""
        if overview.get('scanners') or overview.get('scanners_v2'):
            scanner_section = ResultTableSection("Scanner Results", auto_collapse=True)
            scanner_section.set_column_order([
                "scanner",
                "status",
                "details"
            ])
            
            scanners = overview.get('scanners', [])
            scanners_v2 = overview.get('scanners_v2', {})
            
            for scanner in scanners:
                row = TableRow({
                    "scanner": scanner.get('name', ''),
                    "status": scanner.get('status', ''),
                    "details": f"Progress: {scanner.get('progress')}%, Score: {scanner.get('percent')}%"
                })
                scanner_section.add_row(row)
            
            for name, result in scanners_v2.items():
                if result:
                    row = TableRow({
                        "scanner": result.get('name', name),
                        "status": result.get('status', ''),
                        "details": f"Progress: {result.get('progress')}%, Score: {result.get('percent')}%"
                    })
                    scanner_section.add_row(row)
            
            main_section.add_subsection(scanner_section)

    def _add_mitre_attack_section(self, overview, main_section):
        """Add MITRE ATT&CK information section"""
        if overview.get('mitre_attcks'):
            attack_section = ResultTableSection("MITRE ATT&CK Techniques")
            attack_section.set_column_order([
                "tactic",
                "technique",
                "id",
                "indicators"
            ])
            
            total_malicious = 0
            total_suspicious = 0
            
            for technique in overview['mitre_attcks']:
                if '_truncated_info_' in technique:
                    continue
                    
                malicious_count = technique.get('malicious_identifiers_count', 0)
                suspicious_count = technique.get('suspicious_identifiers_count', 0)
                total_malicious += malicious_count
                total_suspicious += suspicious_count
                
                indicators = (
                    f"Malicious: {malicious_count}, "
                    f"Suspicious: {suspicious_count}, "
                    f"Informative: {technique.get('informative_identifiers_count', 0)}"
                )
                
                row = TableRow({
                    "tactic": technique.get('tactic', ''),
                    "technique": technique.get('technique', ''),
                    "id": technique.get('attck_id', ''),
                    "indicators": indicators
                })
                attack_section.add_row(row)
                
                if technique.get('attck_id'):
                    attack_section.add_tag('technique.id', technique['attck_id'])
            
            if total_malicious > 2 or (total_malicious + total_suspicious) > 5:
                self.log.info(f"Multiple MITRE ATT&CK indicators: {total_malicious} malicious, {total_suspicious} suspicious")
                attack_section.set_heuristic(6)
                    
            main_section.add_subsection(attack_section)

    def _add_signature_stats_section(self, overview, main_section):
        """Add signature statistics section"""
        if overview.get('signatures'):
            total_signatures = len(overview['signatures'])
            stats_section = ResultSection("Signature Statistics")
            stats_section.add_line(f"Total Signatures Detected: {total_signatures}")
            
            if total_signatures > 100:
                self.log.info(f"High number of signatures detected: {total_signatures}")
                stats_section.set_heuristic(7)
                
            main_section.add_subsection(stats_section)

    def _add_behavior_section(self, overview, main_section):
        """Add behavioral analysis section grouped by threat level"""
        if overview.get('signatures'):
            malicious_sigs = []
            suspicious_sigs = []
            informative_sigs = []
            
            for sig in overview['signatures']:
                if '_truncated_info_' in sig:
                    continue
                    
                threat_level = sig.get('threat_level', 0)
                if threat_level >= 2:
                    malicious_sigs.append(sig)
                elif threat_level == 1:
                    suspicious_sigs.append(sig)
                else:
                    informative_sigs.append(sig)
            
            # Helper to create table sections
            def _create_sig_table(title, sigs, heur_id=None):
                if not sigs:
                    return None
                    
                section = ResultTableSection(title)
                section.set_column_order([
                    "name",
                    "category",
                    "threat_level",
                    "attack_id"
                ])
                
                for sig in sigs:
                    row = TableRow({
                        "name": sig.get('name', ''),
                        "category": sig.get('category', ''),
                        "threat_level": f"{sig.get('threat_level_human', '')} ({sig.get('threat_level', '')})",
                        "attack_id": sig.get('attck_id', '')
                    })
                    section.add_row(row)
                    
                    if sig.get('attck_id'):
                        section.add_tag('technique.id', sig['attck_id'])
                        
                if heur_id:
                    section.set_heuristic(heur_id)
                return section

            # Add Malicious Behavior
            malicious_section = _create_sig_table("Malicious Behavior", malicious_sigs, heur_id=10)
            if malicious_section:
                main_section.add_subsection(malicious_section)
                
            # Add Suspicious Behavior
            suspicious_section = _create_sig_table("Suspicious Behavior", suspicious_sigs, heur_id=11)
            if suspicious_section:
                main_section.add_subsection(suspicious_section)
                
            # Add Informative Behavior
            informative_section = _create_sig_table("Informative Behavior", informative_sigs)
            if informative_section:
                informative_section.auto_collapse = True
                main_section.add_subsection(informative_section)

    def _add_crowdstrike_analysis(self, overview, main_section):
        """Add CrowdStrike AI analysis section"""
        if overview.get('crowdstrike_ai', {}).get('executable_process_memory_analysis'):
            cs_section = ResultTableSection("CrowdStrike Memory Analysis")
            cs_section.set_column_order([
                "process",
                "pid",
                "verdict",
                "path"
            ])
            
            has_malicious = False
            has_suspicious = False
            
            for analysis in overview['crowdstrike_ai']['executable_process_memory_analysis']:
                if '_truncated_info_' in analysis:
                    continue
                    
                verdict = analysis.get('verdict', '').lower()
                if verdict == 'malicious':
                    has_malicious = True
                elif verdict == 'suspicious':
                    has_suspicious = True
                
                row = TableRow({
                    "process": analysis.get('file_process', ''),
                    "pid": analysis.get('file_process_pid', ''),
                    "verdict": verdict,
                    "path": analysis.get('file_process_disc_pathway', '')
                })
                cs_section.add_row(row)
                
                if analysis.get('file_process'):
                    cs_section.add_tag('dynamic.process.name', analysis['file_process'])
                if analysis.get('file_process_sha256'):
                    cs_section.add_tag('dynamic.process.file.sha256', analysis['file_process_sha256'])
            
            if has_malicious:
                self.log.info("CrowdStrike detected malicious process memory")
                cs_section.set_heuristic(4)
            elif has_suspicious:
                self.log.info("CrowdStrike detected suspicious process memory")
                cs_section.set_heuristic(5)
                    
            main_section.add_subsection(cs_section)

    def _add_process_section(self, overview, main_section):
        """Add process activity section if available"""
        if overview.get('processes'):
            process_section = ResultTableSection("Process Activity")
            process_section.set_column_order([
                "process_name",
                "pid",
                "command_line"
            ])
            
            for process in overview['processes']:
                row = TableRow({
                    "process_name": process.get('name', ''),
                    "pid": str(process.get('pid', '')),
                    "command_line": process.get('command_line', '')
                })
                process_section.add_row(row)
                
                if process.get('name'):
                    process_section.add_tag('dynamic.process.name', process['name'])
                if process.get('command_line'):
                    process_section.add_tag('dynamic.process.command_line', process['command_line'])
                    
            main_section.add_subsection(process_section)

    def _add_network_section(self, overview, main_section):
        """Add network activity section if available"""
        has_network_data = False
        network_section = ResultSection("Network Activity")
        
        if overview.get('domains'):
            has_network_data = True
            network_section.add_line("Domains:")
            for domain in overview['domains']:
                network_section.add_line(f"  {domain}")
                network_section.add_tag('network.dynamic.domain', domain)
        
        if overview.get('hosts'):
            has_network_data = True
            network_section.add_line("\nHosts:")
            for host in overview['hosts']:
                network_section.add_line(f"  {host}")
                network_section.add_tag('network.dynamic.ip', host)
        
        if overview.get('compromised_hosts'):
            has_network_data = True
            network_section.add_line("\nCompromised Hosts:")
            for host in overview['compromised_hosts']:
                network_section.add_line(f"  {host}")
                network_section.add_tag('network.dynamic.ip', host)
        
        if has_network_data:
            main_section.add_subsection(network_section)