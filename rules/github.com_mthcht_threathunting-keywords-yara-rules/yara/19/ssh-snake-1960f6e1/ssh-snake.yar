rule SSH_Snake
{
    meta:
        description = "Detection patterns for the tool 'SSH-Snake' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSH-Snake"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sSnake\.sh\s/
                        $string2 = /\sSnake\.sh/ nocase ascii wide
                        $string3 = /\/badcert\.pem/
                        $string4 = /\/badkey\.pem/
                        $string5 = /\/Snake\.nocomments\.sh/ nocase ascii wide
                        $string6 = /\/Snake\.sh/ nocase ascii wide
                        $string7 = /\/SSH\-Snake\.git/ nocase ascii wide
                        $string8 = "/SSH-Snake/" nocase ascii wide
                        $string9 = /\[\!\]\sInvalid\ssandbox\sevasion\stechnique\sprovided\!/ nocase ascii wide
                        $string10 = /\[\+\]\sDirect\ssyscalls\shave\sbeen\sdisabled\,\sgetting\sAPI\sfuncs\sfrom\sntdll\sin\smemory\!/ nocase ascii wide
                        $string11 = /\[\+\]\sInjecting\sinto\sexisting\sprocess/ nocase ascii wide
                        $string12 = /\[\+\]\sNTDLL\sunhooking\senabled/ nocase ascii wide
                        $string13 = /\[\+\]\sPPID\sSpoofing\shas\sbeen\sdisabled/ nocase ascii wide
                        $string14 = /\[\+\]\sSysWhispers\sis\snot\scompatible\swith\sObfuscator\-LLVM\;\sswitching\sto\sGetSyscallStub/ nocase ascii wide
                        $string15 = /\[\+\]\sUsing\sDLL\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string16 = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string17 = /\[\+\]\sUsing\shostname\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string18 = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile\sstub\.\.\./ nocase ascii wide
                        $string19 = /\[\+\]\sUsing\ssleep\stechnique\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string20 = /\[\+\]\sUsing\sSysWhispers2\sfor\ssyscalls/ nocase ascii wide
                        $string21 = /\[\+\]\sUsing\sSysWhispers3\sfor\ssyscalls/ nocase ascii wide
                        $string22 = /\[\+\]\sUsing\susername\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string23 = /\[\+\]\sValid\sshellcode\sexecution\smethods\sare\:\sPoolPartyModuleStomping/ nocase ascii wide
                        $string24 = "MegaManSec/SSH-Snake" nocase ascii wide
                        $string25 = /Shellcode\spath\schanged\:.{0,1000}shellcode_path/ nocase ascii wide
                        $string26 = /SSHSnake\.log/ nocase ascii wide
                        $string27 = "SSH-Snake-main" nocase ascii wide

    condition:
        any of them
}