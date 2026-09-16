rule rule_AutoRecon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AutoRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AutoRecon_offensive_tool_keyword = /\sautorecon\.py\s/ nocase ascii wide
                        $string2_AutoRecon_offensive_tool_keyword = /\/AutoRecon\.git/ nocase ascii wide
                        $string3_AutoRecon_offensive_tool_keyword = /\/bruteforce\-ftp\.py/ nocase ascii wide
                        $string4_AutoRecon_offensive_tool_keyword = /\/bruteforce\-http\.py/ nocase ascii wide
                        $string5_AutoRecon_offensive_tool_keyword = /\/bruteforce\-rdp\.py/ nocase ascii wide
                        $string6_AutoRecon_offensive_tool_keyword = /\/bruteforce\-smb\.py/ nocase ascii wide
                        $string7_AutoRecon_offensive_tool_keyword = /\/bruteforce\-ssh\.py/ nocase ascii wide
                        $string8_AutoRecon_offensive_tool_keyword = /\/dirbuster\.py/ nocase ascii wide
                        $string9_AutoRecon_offensive_tool_keyword = /\/dnsrecon\.py/ nocase ascii wide
                        $string10_AutoRecon_offensive_tool_keyword = /\/dnsrecon\-subdomain\-bruteforce\.py/ nocase ascii wide
                        $string11_AutoRecon_offensive_tool_keyword = /\/dns\-zone\-transfer\.py/ nocase ascii wide
                        $string12_AutoRecon_offensive_tool_keyword = /\/enum4linux\.py/
                        $string13_AutoRecon_offensive_tool_keyword = /\/oracle\-patator\.py/ nocase ascii wide
                        $string14_AutoRecon_offensive_tool_keyword = /\/oracle\-scanner\.py/ nocase ascii wide
                        $string15_AutoRecon_offensive_tool_keyword = /\/oracle\-tnscmd\.py/ nocase ascii wide
                        $string16_AutoRecon_offensive_tool_keyword = /\/rpcdump\.py/ nocase ascii wide
                        $string17_AutoRecon_offensive_tool_keyword = /\/rsync\-list\-files\.py/ nocase ascii wide
                        $string18_AutoRecon_offensive_tool_keyword = /\/sipvicious\.py/ nocase ascii wide
                        $string19_AutoRecon_offensive_tool_keyword = /\/smbmap\.py/ nocase ascii wide
                        $string20_AutoRecon_offensive_tool_keyword = /\/smb\-vuln\.py/ nocase ascii wide
                        $string21_AutoRecon_offensive_tool_keyword = /\/wpscan\.py/ nocase ascii wide
                        $string22_AutoRecon_offensive_tool_keyword = /\\AutoRecon\-main/ nocase ascii wide
                        $string23_AutoRecon_offensive_tool_keyword = /\\bruteforce\-ftp\.py/ nocase ascii wide
                        $string24_AutoRecon_offensive_tool_keyword = /\\bruteforce\-http\.py/ nocase ascii wide
                        $string25_AutoRecon_offensive_tool_keyword = /\\bruteforce\-rdp\.py/ nocase ascii wide
                        $string26_AutoRecon_offensive_tool_keyword = /\\bruteforce\-smb\.py/ nocase ascii wide
                        $string27_AutoRecon_offensive_tool_keyword = /\\bruteforce\-ssh\.py/ nocase ascii wide
                        $string28_AutoRecon_offensive_tool_keyword = /\\dirbuster\.py/ nocase ascii wide
                        $string29_AutoRecon_offensive_tool_keyword = /\\dnsrecon\.py/ nocase ascii wide
                        $string30_AutoRecon_offensive_tool_keyword = /\\dnsrecon\-subdomain\-bruteforce\.py/ nocase ascii wide
                        $string31_AutoRecon_offensive_tool_keyword = /\\dns\-zone\-transfer\.py/ nocase ascii wide
                        $string32_AutoRecon_offensive_tool_keyword = /\\enum4linux\.py/ nocase ascii wide
                        $string33_AutoRecon_offensive_tool_keyword = /\\ldap\-search\.py/ nocase ascii wide
                        $string34_AutoRecon_offensive_tool_keyword = /\\lookup\-sid\.py/ nocase ascii wide
                        $string35_AutoRecon_offensive_tool_keyword = /\\nbtscan\.py/ nocase ascii wide
                        $string36_AutoRecon_offensive_tool_keyword = /\\nikto\.py/ nocase ascii wide
                        $string37_AutoRecon_offensive_tool_keyword = /\\nmap\-ajp\.py/ nocase ascii wide
                        $string38_AutoRecon_offensive_tool_keyword = /\\nmap\-cassandra\.py/ nocase ascii wide
                        $string39_AutoRecon_offensive_tool_keyword = /\\nmap\-cups\.py/ nocase ascii wide
                        $string40_AutoRecon_offensive_tool_keyword = /\\nmap\-distccd\.py/ nocase ascii wide
                        $string41_AutoRecon_offensive_tool_keyword = /\\nmap\-dns\.py/ nocase ascii wide
                        $string42_AutoRecon_offensive_tool_keyword = /\\nmap\-finger\.py/ nocase ascii wide
                        $string43_AutoRecon_offensive_tool_keyword = /\\nmap\-ftp\.py/ nocase ascii wide
                        $string44_AutoRecon_offensive_tool_keyword = /\\nmap\-http\.py/ nocase ascii wide
                        $string45_AutoRecon_offensive_tool_keyword = /\\nmap\-imap\.py/ nocase ascii wide
                        $string46_AutoRecon_offensive_tool_keyword = /\\nmap\-irc\.py/ nocase ascii wide
                        $string47_AutoRecon_offensive_tool_keyword = /\\nmap\-kerberos\.py/ nocase ascii wide
                        $string48_AutoRecon_offensive_tool_keyword = /\\nmap\-ldap\.py/ nocase ascii wide
                        $string49_AutoRecon_offensive_tool_keyword = /\\nmap\-mongodb\.py/ nocase ascii wide
                        $string50_AutoRecon_offensive_tool_keyword = /\\nmap\-mountd\.py/ nocase ascii wide
                        $string51_AutoRecon_offensive_tool_keyword = /\\nmap\-msrpc\.py/ nocase ascii wide
                        $string52_AutoRecon_offensive_tool_keyword = /\\nmap\-mssql\.py/ nocase ascii wide
                        $string53_AutoRecon_offensive_tool_keyword = /\\nmap\-multicast\-dns\.py/ nocase ascii wide
                        $string54_AutoRecon_offensive_tool_keyword = /\\nmap\-mysql\.py/ nocase ascii wide
                        $string55_AutoRecon_offensive_tool_keyword = /\\nmap\-nfs\.py/ nocase ascii wide
                        $string56_AutoRecon_offensive_tool_keyword = /\\nmap\-nntp\.py/ nocase ascii wide
                        $string57_AutoRecon_offensive_tool_keyword = /\\nmap\-ntp\.py/ nocase ascii wide
                        $string58_AutoRecon_offensive_tool_keyword = /\\nmap\-oracle\.py/ nocase ascii wide
                        $string59_AutoRecon_offensive_tool_keyword = /\\nmap\-pop3\.py/ nocase ascii wide
                        $string60_AutoRecon_offensive_tool_keyword = /\\nmap\-rdp\.py/ nocase ascii wide
                        $string61_AutoRecon_offensive_tool_keyword = /\\nmap\-redis\.py/ nocase ascii wide
                        $string62_AutoRecon_offensive_tool_keyword = /\\nmap\-rmi\.py/ nocase ascii wide
                        $string63_AutoRecon_offensive_tool_keyword = /\\nmap\-rsync\.py/ nocase ascii wide
                        $string64_AutoRecon_offensive_tool_keyword = /\\nmap\-sip\.py/ nocase ascii wide
                        $string65_AutoRecon_offensive_tool_keyword = /\\nmap\-smb\.py/ nocase ascii wide
                        $string66_AutoRecon_offensive_tool_keyword = /\\nmap\-smtp\.py/ nocase ascii wide
                        $string67_AutoRecon_offensive_tool_keyword = /\\nmap\-snmp\.py/ nocase ascii wide
                        $string68_AutoRecon_offensive_tool_keyword = /\\nmap\-ssh\.py/ nocase ascii wide
                        $string69_AutoRecon_offensive_tool_keyword = /\\nmap\-telnet\.py/ nocase ascii wide
                        $string70_AutoRecon_offensive_tool_keyword = /\\nmap\-tftp\.py/ nocase ascii wide
                        $string71_AutoRecon_offensive_tool_keyword = /\\nmap\-vnc\.py/ nocase ascii wide
                        $string72_AutoRecon_offensive_tool_keyword = /\\onesixtyone\.py/ nocase ascii wide
                        $string73_AutoRecon_offensive_tool_keyword = /\\oracle\-patator\.py/ nocase ascii wide
                        $string74_AutoRecon_offensive_tool_keyword = /\\oracle\-scanner\.py/ nocase ascii wide
                        $string75_AutoRecon_offensive_tool_keyword = /\\oracle\-tnscmd\.py/ nocase ascii wide
                        $string76_AutoRecon_offensive_tool_keyword = /\\rpcdump\.py/ nocase ascii wide
                        $string77_AutoRecon_offensive_tool_keyword = /\\smbmap\.py/ nocase ascii wide
                        $string78_AutoRecon_offensive_tool_keyword = "_smtp_user-enum_hydra_" nocase ascii wide
                        $string79_AutoRecon_offensive_tool_keyword = /_snmp_snmpwalk\.txt/ nocase ascii wide
                        $string80_AutoRecon_offensive_tool_keyword = /_snmp_snmpwalk_process_paths\.txt/ nocase ascii wide
                        $string81_AutoRecon_offensive_tool_keyword = /_snmp_snmpwalk_running_processes\.txt/ nocase ascii wide
                        $string82_AutoRecon_offensive_tool_keyword = /_snmp_snmpwalk_software_names\.txt/ nocase ascii wide
                        $string83_AutoRecon_offensive_tool_keyword = /_snmp_snmpwalk_storage_units\.txt/ nocase ascii wide
                        $string84_AutoRecon_offensive_tool_keyword = /_snmp_snmpwalk_system_processes\.txt/ nocase ascii wide
                        $string85_AutoRecon_offensive_tool_keyword = /_snmp_snmpwalk_tcp_ports\.txt/ nocase ascii wide
                        $string86_AutoRecon_offensive_tool_keyword = /_snmp_snmpwalk_user_accounts\.txt/ nocase ascii wide
                        $string87_AutoRecon_offensive_tool_keyword = "apt install seclists" nocase ascii wide
                        $string88_AutoRecon_offensive_tool_keyword = "autorecon -t " nocase ascii wide
                        $string89_AutoRecon_offensive_tool_keyword = /AutoRecon\\autorecon\.py/ nocase ascii wide
                        $string90_AutoRecon_offensive_tool_keyword = /darkweb2017\-top100\.txt/ nocase ascii wide
                        $string91_AutoRecon_offensive_tool_keyword = /import.{0,100}autorecon\.config/ nocase ascii wide
                        $string92_AutoRecon_offensive_tool_keyword = /import.{0,100}autorecon\.plugins/ nocase ascii wide
                        $string93_AutoRecon_offensive_tool_keyword = "pip uninstall autorecon" nocase ascii wide
                        $string94_AutoRecon_offensive_tool_keyword = "pipx upgrade autorecon" nocase ascii wide
                        $string95_AutoRecon_offensive_tool_keyword = /smbmap\-execute\-command\.txt/ nocase ascii wide
                        $string96_AutoRecon_offensive_tool_keyword = /smbmap\-list\-contents\.txt/ nocase ascii wide
                        $string97_AutoRecon_offensive_tool_keyword = /smbmap\-share\-permissions\.txt/ nocase ascii wide
                        $string98_AutoRecon_offensive_tool_keyword = /smtp\-user\-enum\.py/ nocase ascii wide
                        $string99_AutoRecon_offensive_tool_keyword = /subdomain\-enumeration\.py/ nocase ascii wide
                        $string100_AutoRecon_offensive_tool_keyword = /subdomains\-top1million\-110000\.txt/ nocase ascii wide
                        $string101_AutoRecon_offensive_tool_keyword = "Tib3rius/AutoRecon" nocase ascii wide
                        $string102_AutoRecon_offensive_tool_keyword = /top\-usernames\-shortlist\.txt/ nocase ascii wide
                        $string103_AutoRecon_offensive_tool_keyword = /virtual\-host\-enumeration\.py/ nocase ascii wide
                        $string104_AutoRecon_offensive_tool_keyword = /winrm\-detection\.py/ nocase ascii wide
                        $string105_AutoRecon_offensive_tool_keyword = /wkhtmltoimage\.py/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}