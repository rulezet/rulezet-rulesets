rule rule_mail_in_the_middle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mail-in-the-middle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mail-in-the-middle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mail_in_the_middle_offensive_tool_keyword = /\/DiscordBot\.py/ nocase ascii wide
                        $string2_mail_in_the_middle_offensive_tool_keyword = /\/forwardedemails\.txt/ nocase ascii wide
                        $string3_mail_in_the_middle_offensive_tool_keyword = /\/Maitm\/Bells\.py/
                        $string4_mail_in_the_middle_offensive_tool_keyword = /\/tmp\/Phishing\/documentation\.pdf\.zip/
                        $string5_mail_in_the_middle_offensive_tool_keyword = /\/var\/log\/apache2\/forensic_log\-10080\.log/
                        $string6_mail_in_the_middle_offensive_tool_keyword = /\[\!\]\sInvalid\ssandbox\sevasion\stechnique\sprovided\!/ nocase ascii wide
                        $string7_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sDirect\ssyscalls\shave\sbeen\sdisabled\,\sgetting\sAPI\sfuncs\sfrom\sntdll\sin\smemory\!/ nocase ascii wide
                        $string8_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sInjecting\sinto\sexisting\sprocess/ nocase ascii wide
                        $string9_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sNTDLL\sunhooking\senabled/ nocase ascii wide
                        $string10_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sPPID\sSpoofing\shas\sbeen\sdisabled/ nocase ascii wide
                        $string11_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sSysWhispers\sis\snot\scompatible\swith\sObfuscator\-LLVM\;\sswitching\sto\sGetSyscallStub/ nocase ascii wide
                        $string12_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sUsing\sDLL\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string13_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string14_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sUsing\shostname\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string15_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile\sstub\.\.\./ nocase ascii wide
                        $string16_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sUsing\ssleep\stechnique\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string17_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sUsing\sSysWhispers2\sfor\ssyscalls/ nocase ascii wide
                        $string18_mail_in_the_middle_offensive_tool_keyword = /\[\+\]\sUsing\sSysWhispers3\sfor\ssyscalls/ nocase ascii wide
                        $string19_mail_in_the_middle_offensive_tool_keyword = /_mailinthemiddle\.log/ nocase ascii wide
                        $string20_mail_in_the_middle_offensive_tool_keyword = /change_sandbox_evasion_method\(/ nocase ascii wide
                        $string21_mail_in_the_middle_offensive_tool_keyword = /change_shellcode_exec_method\(/ nocase ascii wide
                        $string22_mail_in_the_middle_offensive_tool_keyword = "Ding Ding Ding! Email opened!" nocase ascii wide
                        $string23_mail_in_the_middle_offensive_tool_keyword = "docker build -t maitm " nocase ascii wide
                        $string24_mail_in_the_middle_offensive_tool_keyword = "docker run --rm -ti maitm -" nocase ascii wide
                        $string25_mail_in_the_middle_offensive_tool_keyword = "from DiscordBot import MitmPuppeter" nocase ascii wide
                        $string26_mail_in_the_middle_offensive_tool_keyword = /from\sMaitm\.Maitm\s/ nocase ascii wide
                        $string27_mail_in_the_middle_offensive_tool_keyword = "LABEL name=\"Maitm\"" nocase ascii wide
                        $string28_mail_in_the_middle_offensive_tool_keyword = /logs\/maitm\.log\\"/ nocase ascii wide
                        $string29_mail_in_the_middle_offensive_tool_keyword = /mail\-in\-the\-middle\.py/ nocase ascii wide

    condition:
        any of them
}