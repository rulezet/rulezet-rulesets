rule GTFONow
{
    meta:
        description = "Detection patterns for the tool 'GTFONow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GTFONow"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sgtfobin_update\.py/ nocase ascii wide
                        $string2 = /\sgtfonow\.py/ nocase ascii wide
                        $string3 = /\slibpwn\.c/ nocase ascii wide
                        $string4 = /\slibpwn\.so/ nocase ascii wide
                        $string5 = /\stest_privesc\.py/ nocase ascii wide
                        $string6 = /\/gtfobin_update\.py/ nocase ascii wide
                        $string7 = /\/gtfonow\.py/ nocase ascii wide
                        $string8 = "/home/lowpriv/"
                        $string9 = /\/test_privesc\.py/ nocase ascii wide
                        $string10 = /\/tmp\/gtfokey\.pub/
                        $string11 = /\/tmp\/libpwn\.c/
                        $string12 = /\/tmp\/libpwn\.so/
                        $string13 = /\[\!\]\sFound\sexploitable\ssgid\sbinary/ nocase ascii wide
                        $string14 = /\[\!\]\sFound\sexploitable\sSudo\sNOPASSWD\sbinary/
                        $string15 = /\[\!\]\sFound\sexploitable\ssuid\sbinary/ nocase ascii wide
                        $string16 = /\[\+\]\sSpawning\sroot\sshell/ nocase ascii wide
                        $string17 = /\\gtfonow\.py/ nocase ascii wide
                        $string18 = "1b220d5538e63244c3b81a0c7a83ebb9ac7b0cdaed9f3e84057a812d7192b9b2" nocase ascii wide
                        $string19 = "7c8dcea2da2cd78b706f7e08ff49f7733008ce357fba21777d17334abf0458a6" nocase ascii wide
                        $string20 = /check_sudo_nopasswd_binaries\(/
                        $string21 = /cron_priv_esc\(payload/ nocase ascii wide
                        $string22 = "db62ef03d6be4778d3ec0fd2f6cb2cf030f02a70efa1f30850b27e0cefd50e9e" nocase ascii wide
                        $string23 = /display_privilege_escalation_options\(/ nocase ascii wide
                        $string24 = /execute_payload\(priv_esc/ nocase ascii wide
                        $string25 = "Frissi0n/GTFONow" nocase ascii wide
                        $string26 = /from\sgtfonow\./ nocase ascii wide
                        $string27 = "getcap not found in PATH, cannot escalate using capabilities" nocase ascii wide
                        $string28 = /gtfonow\.py\s\-a/ nocase ascii wide
                        $string29 = /is_binary_in_gtfobins\(/ nocase ascii wide
                        $string30 = /perform_privilege_escalation_checks\(/ nocase ascii wide
                        $string31 = /ssh_key_privesc\(payload/ nocase ascii wide
                        $string32 = /ssh_write_privesc\(payload/ nocase ascii wide
                        $string33 = "ssh-keygen not found in PATH, cannot escalate using SSH key" nocase ascii wide
                        $string34 = "Thanks for using GTFONow!" nocase ascii wide

    condition:
        any of them
}