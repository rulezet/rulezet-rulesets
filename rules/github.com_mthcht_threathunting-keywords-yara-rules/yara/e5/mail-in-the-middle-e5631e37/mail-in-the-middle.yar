rule mail_in_the_middle
{
    meta:
        description = "Detection patterns for the tool 'mail-in-the-middle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mail-in-the-middle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DiscordBot\.py/ nocase ascii wide
                        $string2 = /\/forwardedemails\.txt/ nocase ascii wide
                        $string3 = /\/Maitm\/Bells\.py/
                        $string4 = /\/tmp\/Phishing\/documentation\.pdf\.zip/
                        $string5 = /\/var\/log\/apache2\/forensic_log\-10080\.log/
                        $string6 = /\[\!\]\sInvalid\ssandbox\sevasion\stechnique\sprovided\!/ nocase ascii wide
                        $string7 = /\[\+\]\sDirect\ssyscalls\shave\sbeen\sdisabled\,\sgetting\sAPI\sfuncs\sfrom\sntdll\sin\smemory\!/ nocase ascii wide
                        $string8 = /\[\+\]\sInjecting\sinto\sexisting\sprocess/ nocase ascii wide
                        $string9 = /\[\+\]\sNTDLL\sunhooking\senabled/ nocase ascii wide
                        $string10 = /\[\+\]\sPPID\sSpoofing\shas\sbeen\sdisabled/ nocase ascii wide
                        $string11 = /\[\+\]\sSysWhispers\sis\snot\scompatible\swith\sObfuscator\-LLVM\;\sswitching\sto\sGetSyscallStub/ nocase ascii wide
                        $string12 = /\[\+\]\sUsing\sDLL\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string13 = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string14 = /\[\+\]\sUsing\shostname\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string15 = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile\sstub\.\.\./ nocase ascii wide
                        $string16 = /\[\+\]\sUsing\ssleep\stechnique\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string17 = /\[\+\]\sUsing\sSysWhispers2\sfor\ssyscalls/ nocase ascii wide
                        $string18 = /\[\+\]\sUsing\sSysWhispers3\sfor\ssyscalls/ nocase ascii wide
                        $string19 = /_mailinthemiddle\.log/ nocase ascii wide
                        $string20 = /change_sandbox_evasion_method\(/ nocase ascii wide
                        $string21 = /change_shellcode_exec_method\(/ nocase ascii wide
                        $string22 = "Ding Ding Ding! Email opened!" nocase ascii wide
                        $string23 = "docker build -t maitm " nocase ascii wide
                        $string24 = "docker run --rm -ti maitm -" nocase ascii wide
                        $string25 = "from DiscordBot import MitmPuppeter" nocase ascii wide
                        $string26 = /from\sMaitm\.Maitm\s/ nocase ascii wide
                        $string27 = "LABEL name=\"Maitm\"" nocase ascii wide
                        $string28 = /logs\/maitm\.log\\"/ nocase ascii wide
                        $string29 = /mail\-in\-the\-middle\.py/ nocase ascii wide
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