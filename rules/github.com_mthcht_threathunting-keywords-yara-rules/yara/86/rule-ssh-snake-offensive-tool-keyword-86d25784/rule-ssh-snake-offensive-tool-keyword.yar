rule rule_SSH_Snake_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SSH-Snake' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSH-Snake"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SSH_Snake_offensive_tool_keyword = /\sSnake\.sh\s/
                        $string2_SSH_Snake_offensive_tool_keyword = /\sSnake\.sh/ nocase ascii wide
                        $string3_SSH_Snake_offensive_tool_keyword = /\/badcert\.pem/
                        $string4_SSH_Snake_offensive_tool_keyword = /\/badkey\.pem/
                        $string5_SSH_Snake_offensive_tool_keyword = /\/Snake\.nocomments\.sh/ nocase ascii wide
                        $string6_SSH_Snake_offensive_tool_keyword = /\/Snake\.sh/ nocase ascii wide
                        $string7_SSH_Snake_offensive_tool_keyword = /\/SSH\-Snake\.git/ nocase ascii wide
                        $string8_SSH_Snake_offensive_tool_keyword = "/SSH-Snake/" nocase ascii wide
                        $string9_SSH_Snake_offensive_tool_keyword = /\[\!\]\sInvalid\ssandbox\sevasion\stechnique\sprovided\!/ nocase ascii wide
                        $string10_SSH_Snake_offensive_tool_keyword = /\[\+\]\sDirect\ssyscalls\shave\sbeen\sdisabled\,\sgetting\sAPI\sfuncs\sfrom\sntdll\sin\smemory\!/ nocase ascii wide
                        $string11_SSH_Snake_offensive_tool_keyword = /\[\+\]\sInjecting\sinto\sexisting\sprocess/ nocase ascii wide
                        $string12_SSH_Snake_offensive_tool_keyword = /\[\+\]\sNTDLL\sunhooking\senabled/ nocase ascii wide
                        $string13_SSH_Snake_offensive_tool_keyword = /\[\+\]\sPPID\sSpoofing\shas\sbeen\sdisabled/ nocase ascii wide
                        $string14_SSH_Snake_offensive_tool_keyword = /\[\+\]\sSysWhispers\sis\snot\scompatible\swith\sObfuscator\-LLVM\;\sswitching\sto\sGetSyscallStub/ nocase ascii wide
                        $string15_SSH_Snake_offensive_tool_keyword = /\[\+\]\sUsing\sDLL\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string16_SSH_Snake_offensive_tool_keyword = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string17_SSH_Snake_offensive_tool_keyword = /\[\+\]\sUsing\shostname\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string18_SSH_Snake_offensive_tool_keyword = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile\sstub\.\.\./ nocase ascii wide
                        $string19_SSH_Snake_offensive_tool_keyword = /\[\+\]\sUsing\ssleep\stechnique\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string20_SSH_Snake_offensive_tool_keyword = /\[\+\]\sUsing\sSysWhispers2\sfor\ssyscalls/ nocase ascii wide
                        $string21_SSH_Snake_offensive_tool_keyword = /\[\+\]\sUsing\sSysWhispers3\sfor\ssyscalls/ nocase ascii wide
                        $string22_SSH_Snake_offensive_tool_keyword = /\[\+\]\sUsing\susername\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string23_SSH_Snake_offensive_tool_keyword = /\[\+\]\sValid\sshellcode\sexecution\smethods\sare\:\sPoolPartyModuleStomping/ nocase ascii wide
                        $string24_SSH_Snake_offensive_tool_keyword = "MegaManSec/SSH-Snake" nocase ascii wide
                        $string25_SSH_Snake_offensive_tool_keyword = /Shellcode\spath\schanged\:.{0,100}shellcode_path/ nocase ascii wide
                        $string26_SSH_Snake_offensive_tool_keyword = /SSHSnake\.log/ nocase ascii wide
                        $string27_SSH_Snake_offensive_tool_keyword = "SSH-Snake-main" nocase ascii wide
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