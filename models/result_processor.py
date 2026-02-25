from assemblyline_v4_service.common.result import ResultSection, ResultTableSection, TableRow, ResultKeyValueSection

class ResultProcessor:
    def __init__(self, logger):
        self.log = logger

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
        
        return main_section

    def _add_summary_section(self, overview, main_section):
        """Add summary section with verdict and threat information"""
        summary_section = ResultKeyValueSection("Analysis Summary")
        
        verdict = overview.get('verdict', 'Unknown')
        summary_section.set_item("Verdict", verdict)
        
        threat_score = overview.get('threat_score')
        if threat_score is not None:
            summary_section.set_item("Threat Score", threat_score)
            if threat_score >= 85:
                self.log.info(f"Critical threat score detected: {threat_score}")
                summary_section.set_heuristic(1)
            elif threat_score >= 70:
                self.log.info(f"High threat score detected: {threat_score}")
                summary_section.set_heuristic(2)
        
        av_detect = overview.get('av_detect')
        if av_detect is not None:
            summary_section.set_item("AV Detection Rate", av_detect)
            if av_detect > 30:
                self.log.info(f"High AV detection rate: {av_detect}")
                summary_section.set_heuristic(3)
        
        if overview.get('vx_family'):
            summary_section.set_item("Malware Family", overview['vx_family'])
            summary_section.add_tag('attribution.family', overview['vx_family'])
            summary_section.set_heuristic(8)
            
        if overview.get('environment_description'):
            summary_section.set_item("Analysis Environment", overview['environment_description'])
            
        if overview.get('sha256'):
            report_url = f"https://www.hybrid-analysis.com/sample/{overview['sha256']}"
            summary_section.set_item("Report Link", report_url)
            
        main_section.add_subsection(summary_section)

    def _add_submission_history(self, overview, main_section):
        """Add submission history section"""
        if overview.get('submissions'):
            history_section = ResultTableSection("Submission History")
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
        file_info = ResultKeyValueSection("File Information")
        
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
            scanner_section = ResultTableSection("Scanner Results")
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

            # Add Malicious Behavior (Heuristic 2)
            malicious_section = _create_sig_table("Malicious Behavior", malicious_sigs, heur_id=2)
            if malicious_section:
                main_section.add_subsection(malicious_section)
                
            # Add Suspicious Behavior (Heuristic 3)
            suspicious_section = _create_sig_table("Suspicious Behavior", suspicious_sigs, heur_id=3)
            if suspicious_section:
                main_section.add_subsection(suspicious_section)
                
            # Add Informative Behavior (No heuristic)
            informative_section = _create_sig_table("Informative Behavior", informative_sigs)
            if informative_section:
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