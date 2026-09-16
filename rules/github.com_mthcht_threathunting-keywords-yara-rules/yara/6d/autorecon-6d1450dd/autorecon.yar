rule AutoRecon
{
    meta:
        description = "Detection patterns for the tool 'AutoRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sautorecon\.py\s/ nocase ascii wide
                        $string2 = /\/AutoRecon\.git/ nocase ascii wide
                        $string3 = /\/bruteforce\-ftp\.py/ nocase ascii wide
                        $string4 = /\/bruteforce\-http\.py/ nocase ascii wide
                        $string5 = /\/bruteforce\-rdp\.py/ nocase ascii wide
                        $string6 = /\/bruteforce\-smb\.py/ nocase ascii wide
                        $string7 = /\/bruteforce\-ssh\.py/ nocase ascii wide
                        $string8 = /\/dirbuster\.py/ nocase ascii wide
                        $string9 = /\/dnsrecon\.py/ nocase ascii wide
                        $string10 = /\/dnsrecon\-subdomain\-bruteforce\.py/ nocase ascii wide
                        $string11 = /\/dns\-zone\-transfer\.py/ nocase ascii wide
                        $string12 = /\/enum4linux\.py/
                        $string13 = /\/oracle\-patator\.py/ nocase ascii wide
                        $string14 = /\/oracle\-scanner\.py/ nocase ascii wide
                        $string15 = /\/oracle\-tnscmd\.py/ nocase ascii wide
                        $string16 = /\/rpcdump\.py/ nocase ascii wide
                        $string17 = /\/rsync\-list\-files\.py/ nocase ascii wide
                        $string18 = /\/sipvicious\.py/ nocase ascii wide
                        $string19 = /\/smbmap\.py/ nocase ascii wide
                        $string20 = /\/smb\-vuln\.py/ nocase ascii wide
                        $string21 = /\/wpscan\.py/ nocase ascii wide
                        $string22 = /\\AutoRecon\-main/ nocase ascii wide
                        $string23 = /\\bruteforce\-ftp\.py/ nocase ascii wide
                        $string24 = /\\bruteforce\-http\.py/ nocase ascii wide
                        $string25 = /\\bruteforce\-rdp\.py/ nocase ascii wide
                        $string26 = /\\bruteforce\-smb\.py/ nocase ascii wide
                        $string27 = /\\bruteforce\-ssh\.py/ nocase ascii wide
                        $string28 = /\\dirbuster\.py/ nocase ascii wide
                        $string29 = /\\dnsrecon\.py/ nocase ascii wide
                        $string30 = /\\dnsrecon\-subdomain\-bruteforce\.py/ nocase ascii wide
                        $string31 = /\\dns\-zone\-transfer\.py/ nocase ascii wide
                        $string32 = /\\enum4linux\.py/ nocase ascii wide
                        $string33 = /\\ldap\-search\.py/ nocase ascii wide
                        $string34 = /\\lookup\-sid\.py/ nocase ascii wide
                        $string35 = /\\nbtscan\.py/ nocase ascii wide
                        $string36 = /\\nikto\.py/ nocase ascii wide
                        $string37 = /\\nmap\-ajp\.py/ nocase ascii wide
                        $string38 = /\\nmap\-cassandra\.py/ nocase ascii wide
                        $string39 = /\\nmap\-cups\.py/ nocase ascii wide
                        $string40 = /\\nmap\-distccd\.py/ nocase ascii wide
                        $string41 = /\\nmap\-dns\.py/ nocase ascii wide
                        $string42 = /\\nmap\-finger\.py/ nocase ascii wide
                        $string43 = /\\nmap\-ftp\.py/ nocase ascii wide
                        $string44 = /\\nmap\-http\.py/ nocase ascii wide
                        $string45 = /\\nmap\-imap\.py/ nocase ascii wide
                        $string46 = /\\nmap\-irc\.py/ nocase ascii wide
                        $string47 = /\\nmap\-kerberos\.py/ nocase ascii wide
                        $string48 = /\\nmap\-ldap\.py/ nocase ascii wide
                        $string49 = /\\nmap\-mongodb\.py/ nocase ascii wide
                        $string50 = /\\nmap\-mountd\.py/ nocase ascii wide
                        $string51 = /\\nmap\-msrpc\.py/ nocase ascii wide
                        $string52 = /\\nmap\-mssql\.py/ nocase ascii wide
                        $string53 = /\\nmap\-multicast\-dns\.py/ nocase ascii wide
                        $string54 = /\\nmap\-mysql\.py/ nocase ascii wide
                        $string55 = /\\nmap\-nfs\.py/ nocase ascii wide
                        $string56 = /\\nmap\-nntp\.py/ nocase ascii wide
                        $string57 = /\\nmap\-ntp\.py/ nocase ascii wide
                        $string58 = /\\nmap\-oracle\.py/ nocase ascii wide
                        $string59 = /\\nmap\-pop3\.py/ nocase ascii wide
                        $string60 = /\\nmap\-rdp\.py/ nocase ascii wide
                        $string61 = /\\nmap\-redis\.py/ nocase ascii wide
                        $string62 = /\\nmap\-rmi\.py/ nocase ascii wide
                        $string63 = /\\nmap\-rsync\.py/ nocase ascii wide
                        $string64 = /\\nmap\-sip\.py/ nocase ascii wide
                        $string65 = /\\nmap\-smb\.py/ nocase ascii wide
                        $string66 = /\\nmap\-smtp\.py/ nocase ascii wide
                        $string67 = /\\nmap\-snmp\.py/ nocase ascii wide
                        $string68 = /\\nmap\-ssh\.py/ nocase ascii wide
                        $string69 = /\\nmap\-telnet\.py/ nocase ascii wide
                        $string70 = /\\nmap\-tftp\.py/ nocase ascii wide
                        $string71 = /\\nmap\-vnc\.py/ nocase ascii wide
                        $string72 = /\\onesixtyone\.py/ nocase ascii wide
                        $string73 = /\\oracle\-patator\.py/ nocase ascii wide
                        $string74 = /\\oracle\-scanner\.py/ nocase ascii wide
                        $string75 = /\\oracle\-tnscmd\.py/ nocase ascii wide
                        $string76 = /\\rpcdump\.py/ nocase ascii wide
                        $string77 = /\\smbmap\.py/ nocase ascii wide
                        $string78 = "_smtp_user-enum_hydra_" nocase ascii wide
                        $string79 = /_snmp_snmpwalk\.txt/ nocase ascii wide
                        $string80 = /_snmp_snmpwalk_process_paths\.txt/ nocase ascii wide
                        $string81 = /_snmp_snmpwalk_running_processes\.txt/ nocase ascii wide
                        $string82 = /_snmp_snmpwalk_software_names\.txt/ nocase ascii wide
                        $string83 = /_snmp_snmpwalk_storage_units\.txt/ nocase ascii wide
                        $string84 = /_snmp_snmpwalk_system_processes\.txt/ nocase ascii wide
                        $string85 = /_snmp_snmpwalk_tcp_ports\.txt/ nocase ascii wide
                        $string86 = /_snmp_snmpwalk_user_accounts\.txt/ nocase ascii wide
                        $string87 = "apt install seclists" nocase ascii wide
                        $string88 = "autorecon -t " nocase ascii wide
                        $string89 = /AutoRecon\\autorecon\.py/ nocase ascii wide
                        $string90 = /darkweb2017\-top100\.txt/ nocase ascii wide
                        $string91 = /import.{0,100}autorecon\.config/ nocase ascii wide
                        $string92 = /import.{0,100}autorecon\.plugins/ nocase ascii wide
                        $string93 = "pip uninstall autorecon" nocase ascii wide
                        $string94 = "pipx upgrade autorecon" nocase ascii wide
                        $string95 = /smbmap\-execute\-command\.txt/ nocase ascii wide
                        $string96 = /smbmap\-list\-contents\.txt/ nocase ascii wide
                        $string97 = /smbmap\-share\-permissions\.txt/ nocase ascii wide
                        $string98 = /smtp\-user\-enum\.py/ nocase ascii wide
                        $string99 = /subdomain\-enumeration\.py/ nocase ascii wide
                        $string100 = /subdomains\-top1million\-110000\.txt/ nocase ascii wide
                        $string101 = "Tib3rius/AutoRecon" nocase ascii wide
                        $string102 = /top\-usernames\-shortlist\.txt/ nocase ascii wide
                        $string103 = /virtual\-host\-enumeration\.py/ nocase ascii wide
                        $string104 = /winrm\-detection\.py/ nocase ascii wide
                        $string105 = /wkhtmltoimage\.py/ nocase ascii wide
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