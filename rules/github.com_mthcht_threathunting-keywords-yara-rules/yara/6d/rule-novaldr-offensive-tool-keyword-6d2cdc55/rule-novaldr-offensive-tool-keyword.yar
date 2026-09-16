rule rule_NovaLdr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NovaLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NovaLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NovaLdr_offensive_tool_keyword = /\s\-f\sraw\s\-e\snone\s\-o\sNova_MSG\.bin/ nocase ascii wide
                        $string2_NovaLdr_offensive_tool_keyword = " -p windows/x64/messagebox TITLE=NovaLdr " nocase ascii wide
                        $string3_NovaLdr_offensive_tool_keyword = /\/NovaLdr\.exe/ nocase ascii wide
                        $string4_NovaLdr_offensive_tool_keyword = /\/NovaLdr\.git/ nocase ascii wide
                        $string5_NovaLdr_offensive_tool_keyword = /\/NoveLdr\.exe/ nocase ascii wide
                        $string6_NovaLdr_offensive_tool_keyword = /\[\-\]\sShellcode\sis\slarger\sthan\sRX\ssection/ nocase ascii wide
                        $string7_NovaLdr_offensive_tool_keyword = /\[\+\]\sEncrypting\sThe\sStack\.\.\.\.\s/ nocase ascii wide
                        $string8_NovaLdr_offensive_tool_keyword = /\[\+\]\sRX\sInjection\saddress\:\s/ nocase ascii wide
                        $string9_NovaLdr_offensive_tool_keyword = /\[\+\]\sThread\shijacking\ssuccessful/ nocase ascii wide
                        $string10_NovaLdr_offensive_tool_keyword = /\[\+\]\sThread\shijacking\ssuccessful/ nocase ascii wide
                        $string11_NovaLdr_offensive_tool_keyword = /\[\+\]\sUnhooking\sthe\sNTDLL\sfor\sProcess\swith\sPID\s/ nocase ascii wide
                        $string12_NovaLdr_offensive_tool_keyword = /\[\+\]\sUnhooking\sthe\sNTDLL\sfrom\sPID\s.{0,1000}\scompleted\ssuccessfully\./ nocase ascii wide
                        $string13_NovaLdr_offensive_tool_keyword = /\\NovaLdr\.exe/ nocase ascii wide
                        $string14_NovaLdr_offensive_tool_keyword = /\\NoveLdr\.exe/ nocase ascii wide
                        $string15_NovaLdr_offensive_tool_keyword = "BlackSnufkin/NovaLdr" nocase ascii wide
                        $string16_NovaLdr_offensive_tool_keyword = /C\:\\\\Users\\\\L\.Ackerman\=/ nocase ascii wide
                        $string17_NovaLdr_offensive_tool_keyword = /encrypted_sleep\(ms\:/ nocase ascii wide
                        $string18_NovaLdr_offensive_tool_keyword = /erase_dos_magic_bytes\(/ nocase ascii wide
                        $string19_NovaLdr_offensive_tool_keyword = "Failed to allocate memory for shellcode:" nocase ascii wide
                        $string20_NovaLdr_offensive_tool_keyword = "Failed to change shellcode memory protection" nocase ascii wide
                        $string21_NovaLdr_offensive_tool_keyword = "Failed to find rx section offset" nocase ascii wide
                        $string22_NovaLdr_offensive_tool_keyword = "Failed to hijack thread:" nocase ascii wide
                        $string23_NovaLdr_offensive_tool_keyword = /Failed\sto\soverwrite\sthe\s\.text\ssection\sof\sntdll\.dll/ nocase ascii wide
                        $string24_NovaLdr_offensive_tool_keyword = "Failed to write shellcode to target process" nocase ascii wide
                        $string25_NovaLdr_offensive_tool_keyword = /In\smemory\sof\sall\sthose\smurdered\sin\sthe\sNova\sparty\smassacre\s7\.10\.2023/ nocase ascii wide
                        $string26_NovaLdr_offensive_tool_keyword = /It2H\@Qp3Xe.{0,1000}sxdc\#KA8\)dbMtI5Q7\&FK/ nocase ascii wide
                        $string27_NovaLdr_offensive_tool_keyword = "janoglezcampos/rust_syscalls" nocase ascii wide
                        $string28_NovaLdr_offensive_tool_keyword = /jmp_hijack_thread\(/ nocase ascii wide
                        $string29_NovaLdr_offensive_tool_keyword = "NovaLdr-main" nocase ascii wide
                        $string30_NovaLdr_offensive_tool_keyword = "Threadless injection failed" nocase ascii wide
                        $string31_NovaLdr_offensive_tool_keyword = /unhook_ntdll\(remote_process/ nocase ascii wide
                        $string32_NovaLdr_offensive_tool_keyword = /xor_encrypt\(/ nocase ascii wide

    condition:
        any of them
}