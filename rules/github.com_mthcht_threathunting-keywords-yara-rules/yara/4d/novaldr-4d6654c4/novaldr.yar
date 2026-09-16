rule NovaLdr
{
    meta:
        description = "Detection patterns for the tool 'NovaLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NovaLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-f\sraw\s\-e\snone\s\-o\sNova_MSG\.bin/ nocase ascii wide
                        $string2 = " -p windows/x64/messagebox TITLE=NovaLdr " nocase ascii wide
                        $string3 = /\/NovaLdr\.exe/ nocase ascii wide
                        $string4 = /\/NovaLdr\.git/ nocase ascii wide
                        $string5 = /\/NoveLdr\.exe/ nocase ascii wide
                        $string6 = /\[\-\]\sShellcode\sis\slarger\sthan\sRX\ssection/ nocase ascii wide
                        $string7 = /\[\+\]\sEncrypting\sThe\sStack\.\.\.\.\s/ nocase ascii wide
                        $string8 = /\[\+\]\sRX\sInjection\saddress\:\s/ nocase ascii wide
                        $string9 = /\[\+\]\sThread\shijacking\ssuccessful/ nocase ascii wide
                        $string10 = /\[\+\]\sThread\shijacking\ssuccessful/ nocase ascii wide
                        $string11 = /\[\+\]\sUnhooking\sthe\sNTDLL\sfor\sProcess\swith\sPID\s/ nocase ascii wide
                        $string12 = /\[\+\]\sUnhooking\sthe\sNTDLL\sfrom\sPID\s.{0,1000}\scompleted\ssuccessfully\./ nocase ascii wide
                        $string13 = /\\NovaLdr\.exe/ nocase ascii wide
                        $string14 = /\\NoveLdr\.exe/ nocase ascii wide
                        $string15 = "BlackSnufkin/NovaLdr" nocase ascii wide
                        $string16 = /C\:\\\\Users\\\\L\.Ackerman\=/ nocase ascii wide
                        $string17 = /encrypted_sleep\(ms\:/ nocase ascii wide
                        $string18 = /erase_dos_magic_bytes\(/ nocase ascii wide
                        $string19 = "Failed to allocate memory for shellcode:" nocase ascii wide
                        $string20 = "Failed to change shellcode memory protection" nocase ascii wide
                        $string21 = "Failed to find rx section offset" nocase ascii wide
                        $string22 = "Failed to hijack thread:" nocase ascii wide
                        $string23 = /Failed\sto\soverwrite\sthe\s\.text\ssection\sof\sntdll\.dll/ nocase ascii wide
                        $string24 = "Failed to write shellcode to target process" nocase ascii wide
                        $string25 = /In\smemory\sof\sall\sthose\smurdered\sin\sthe\sNova\sparty\smassacre\s7\.10\.2023/ nocase ascii wide
                        $string26 = /It2H\@Qp3Xe.{0,1000}sxdc\#KA8\)dbMtI5Q7\&FK/ nocase ascii wide
                        $string27 = "janoglezcampos/rust_syscalls" nocase ascii wide
                        $string28 = /jmp_hijack_thread\(/ nocase ascii wide
                        $string29 = "NovaLdr-main" nocase ascii wide
                        $string30 = "Threadless injection failed" nocase ascii wide
                        $string31 = /unhook_ntdll\(remote_process/ nocase ascii wide
                        $string32 = /xor_encrypt\(/ nocase ascii wide

    condition:
        any of them
}