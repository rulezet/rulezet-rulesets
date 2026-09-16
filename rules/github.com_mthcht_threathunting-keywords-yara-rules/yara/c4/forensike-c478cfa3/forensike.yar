rule Forensike
{
    meta:
        description = "Detection patterns for the tool 'Forensike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Forensike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -c \"!mimikatz\" " nocase ascii wide
                        $string2 = /\sForensike\.ps1/ nocase ascii wide
                        $string3 = /\$dumpDir\\lsass\.txt/ nocase ascii wide
                        $string4 = /\$ForensikeFolder/ nocase ascii wide
                        $string5 = /\/DumpIt\.exe/ nocase ascii wide
                        $string6 = /\/Forensike\.git/ nocase ascii wide
                        $string7 = /\/Forensike\.ps1/ nocase ascii wide
                        $string8 = /\/mimilib\.dll/ nocase ascii wide
                        $string9 = /\\DumpIt\.exe/ nocase ascii wide
                        $string10 = /\\Forensike\.dmp/ nocase ascii wide
                        $string11 = /\\Forensike\.ps1/ nocase ascii wide
                        $string12 = /\\forensike_results\.txt/ nocase ascii wide
                        $string13 = /\\mimilib\.dll/ nocase ascii wide
                        $string14 = /\\Windows\\Temp\\Forensike/ nocase ascii wide
                        $string15 = /\>\[\sSTARTING\sCRASH\sDUMP\sACQUISITION\s\]\</ nocase ascii wide
                        $string16 = /\>\[\sSTARTING\sNT\sHASHES\sEXTRACTION\s\]\</ nocase ascii wide
                        $string17 = "6a484c1db7718949c7027abde97e164c7e7e4e4214e3e29fe48ac4364c0cd23c" nocase ascii wide
                        $string18 = "7ffce7f6d7262f214d78e6b7fd8d07119835cba4b04ce334260665d7c8fb369a" nocase ascii wide
                        $string19 = "bmarchev/Forensike" nocase ascii wide
                        $string20 = "e81284fcd76acab65fcb296db056f50a4fa61eb120581ff2d494006d97f2f762" nocase ascii wide
                        $string21 = "load mimikatz windbg extension, extracts credential from crash dump" nocase ascii wide

    condition:
        any of them
}