rule rule_nanodump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nanodump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nanodump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nanodump_offensive_tool_keyword = /\s\-\-fork\s\-\-write\s.{0,100}\.dmp/ nocase ascii wide
                        $string2_nanodump_offensive_tool_keyword = /\s\-\-load\-dll\s.{0,100}ssp\.dll/ nocase ascii wide
                        $string3_nanodump_offensive_tool_keyword = " nanodump" nocase ascii wide
                        $string4_nanodump_offensive_tool_keyword = " nanodump/" nocase ascii wide
                        $string5_nanodump_offensive_tool_keyword = " --seclogon-duplicate" nocase ascii wide
                        $string6_nanodump_offensive_tool_keyword = " --shtinkering" nocase ascii wide
                        $string7_nanodump_offensive_tool_keyword = " --silent-process-exit " nocase ascii wide
                        $string8_nanodump_offensive_tool_keyword = " SW2_HashSyscall" nocase ascii wide
                        $string9_nanodump_offensive_tool_keyword = /\s\-\-werfault\s.{0,100}\\temp\\/ nocase ascii wide
                        $string10_nanodump_offensive_tool_keyword = /\/load_ssp\.x64\.exe/ nocase ascii wide
                        $string11_nanodump_offensive_tool_keyword = /\/malseclogon\./ nocase ascii wide
                        $string12_nanodump_offensive_tool_keyword = "/nanodump" nocase ascii wide
                        $string13_nanodump_offensive_tool_keyword = /\/ppl\/ppl\.c/ nocase ascii wide
                        $string14_nanodump_offensive_tool_keyword = /\/ppl_dump\./ nocase ascii wide
                        $string15_nanodump_offensive_tool_keyword = /\\load_ssp\.x64\.exe/ nocase ascii wide
                        $string16_nanodump_offensive_tool_keyword = /\\malseclogon\./ nocase ascii wide
                        $string17_nanodump_offensive_tool_keyword = /\\nanodump/ nocase ascii wide
                        $string18_nanodump_offensive_tool_keyword = /\\ppl_dump\./ nocase ascii wide
                        $string19_nanodump_offensive_tool_keyword = /_ppl_dump\.x64/ nocase ascii wide
                        $string20_nanodump_offensive_tool_keyword = /_ppl_dump\.x64\./ nocase ascii wide
                        $string21_nanodump_offensive_tool_keyword = /_ppl_dump_dll\.x64/ nocase ascii wide
                        $string22_nanodump_offensive_tool_keyword = /_ppl_dump_dll\.x86/ nocase ascii wide
                        $string23_nanodump_offensive_tool_keyword = /_ppl_medic\.x64\.dll/ nocase ascii wide
                        $string24_nanodump_offensive_tool_keyword = /_ppl_medic\.x64\.exe/ nocase ascii wide
                        $string25_nanodump_offensive_tool_keyword = /_ppl_medic_dll\.x64\./ nocase ascii wide
                        $string26_nanodump_offensive_tool_keyword = "08f0007bf2c941bb9372682e9cdcc21e59369b6038c70a7a20a7d3507abaa86d" nocase ascii wide
                        $string27_nanodump_offensive_tool_keyword = "0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7, 0x00, 0x00" nocase ascii wide
                        $string28_nanodump_offensive_tool_keyword = "2202732c2585283f93fca9bee4c3f3709530fa450a1bea8bfb925768f38b2bb9" nocase ascii wide
                        $string29_nanodump_offensive_tool_keyword = "4a25a09ed816e1c629945dbd33779ab714d82bebf661557864aa61562ed4298c" nocase ascii wide
                        $string30_nanodump_offensive_tool_keyword = "567639e3dc4355c549e9c9cc42988325cb95a0f6e86004d5679ad3e15af7c6cd" nocase ascii wide
                        $string31_nanodump_offensive_tool_keyword = "56a0e08a01309e17e4e6c753948fd4f341e9a41b1b834b3ce697bffdd90c467b" nocase ascii wide
                        $string32_nanodump_offensive_tool_keyword = "79ef2d4f2ad91311f14fc200acb71e78a47eb9a4f23e776649fb1b0b06c69dd2" nocase ascii wide
                        $string33_nanodump_offensive_tool_keyword = "83536b1df51e5954c757179b70419fe5567df58f3ed029998e6ca82f7c0a15a7" nocase ascii wide
                        $string34_nanodump_offensive_tool_keyword = "8484a8848d429d954636f8c6c170bdd73d96288325b902eb43c3403f0650b5e6" nocase ascii wide
                        $string35_nanodump_offensive_tool_keyword = "8a24643b1ae79babbba0995d870bf0992cfc9acfef6459727c603ef5b61c261f" nocase ascii wide
                        $string36_nanodump_offensive_tool_keyword = "90e767d5fd29fc406847b5ac6151a713643596625209245d3440fd8908ff7427" nocase ascii wide
                        $string37_nanodump_offensive_tool_keyword = "97699449246070bc8195e1cf1f14b94dc2ee429cb03128bb7e7e254981eb71a0" nocase ascii wide
                        $string38_nanodump_offensive_tool_keyword = "a909221a35b3fda0f6149de8e58186909cd0efae15bbba614b9a15d4b7d15fd3" nocase ascii wide
                        $string39_nanodump_offensive_tool_keyword = "be9cd67ca6ef0d87c8dacebef75d1f62b38cff5b8ba4ad2f0eb382ab54081317" nocase ascii wide
                        $string40_nanodump_offensive_tool_keyword = "c18989d8b80f11117c403bc1c8f8afac0a807f1acdf67ecffcf50402164c11eb" nocase ascii wide
                        $string41_nanodump_offensive_tool_keyword = "cdcb96e58514e182d0799884b64872caff34ed0eb552d842015941a7540347e7" nocase ascii wide
                        $string42_nanodump_offensive_tool_keyword = "check_ppl_requirements" nocase ascii wide
                        $string43_nanodump_offensive_tool_keyword = "create_dummy_dll_file" nocase ascii wide
                        $string44_nanodump_offensive_tool_keyword = "create_protected_process_as_user" nocase ascii wide
                        $string45_nanodump_offensive_tool_keyword = "d854d2be5826183cb7c1317e3d920871fd467d5506b70e3c5147599ca2704ee6" nocase ascii wide
                        $string46_nanodump_offensive_tool_keyword = "f2ca48973b72ab97f4cb482062d2ab8778078107767a36062e11243a3265e756" nocase ascii wide
                        $string47_nanodump_offensive_tool_keyword = "f3bdfbd2b36064266a9d9e4452aba93cb97980c37dbe472e0b3b72e1485500ab" nocase ascii wide
                        $string48_nanodump_offensive_tool_keyword = "faa491fa7733cf0c51ffdcf97be3fd48231863ff59b4f6922e11bbb747bf1806" nocase ascii wide
                        $string49_nanodump_offensive_tool_keyword = "get_hijackeable_dllname" nocase ascii wide
                        $string50_nanodump_offensive_tool_keyword = "initialize_fake_thread_state" nocase ascii wide
                        $string51_nanodump_offensive_tool_keyword = "initialize_spoofed_callstack" nocase ascii wide
                        $string52_nanodump_offensive_tool_keyword = "is_proxy_stub_dll_loaded" nocase ascii wide
                        $string53_nanodump_offensive_tool_keyword = /load_ssp\s.{0,100}\.dll/ nocase ascii wide
                        $string54_nanodump_offensive_tool_keyword = /load_ssp\.x64\.exe\s.{0,100}\.dll/ nocase ascii wide
                        $string55_nanodump_offensive_tool_keyword = "map_payload_dll" nocase ascii wide
                        $string56_nanodump_offensive_tool_keyword = "nanodump " nocase ascii wide
                        $string57_nanodump_offensive_tool_keyword = "nanodump -" nocase ascii wide
                        $string58_nanodump_offensive_tool_keyword = /nanodump\./ nocase ascii wide
                        $string59_nanodump_offensive_tool_keyword = /nanodump\.git/ nocase ascii wide
                        $string60_nanodump_offensive_tool_keyword = /nanodump\.x64/ nocase ascii wide
                        $string61_nanodump_offensive_tool_keyword = /nanodump\.x64\.exe/ nocase ascii wide
                        $string62_nanodump_offensive_tool_keyword = /nanodump\.x86/ nocase ascii wide
                        $string63_nanodump_offensive_tool_keyword = "nanodump_ppl_dump" nocase ascii wide
                        $string64_nanodump_offensive_tool_keyword = /nanodump_ppl_dump\.x64/ nocase ascii wide
                        $string65_nanodump_offensive_tool_keyword = /nanodump_ppl_dump\.x86/ nocase ascii wide
                        $string66_nanodump_offensive_tool_keyword = "nanodump_ppl_medic" nocase ascii wide
                        $string67_nanodump_offensive_tool_keyword = /nanodump_ppl_medic\.x64/ nocase ascii wide
                        $string68_nanodump_offensive_tool_keyword = /nanodump_ppl_medic\.x86/ nocase ascii wide
                        $string69_nanodump_offensive_tool_keyword = "nanodump_ssp" nocase ascii wide
                        $string70_nanodump_offensive_tool_keyword = /nanodump_ssp\.x64/ nocase ascii wide
                        $string71_nanodump_offensive_tool_keyword = /nanodump_ssp\.x64\.dll/ nocase ascii wide
                        $string72_nanodump_offensive_tool_keyword = /nanodump_ssp\.x86/ nocase ascii wide
                        $string73_nanodump_offensive_tool_keyword = "NanoDumpWriteDump" nocase ascii wide
                        $string74_nanodump_offensive_tool_keyword = /ppl.{0,100}\s\-\-elevate\-handle\s.{0,100}\.dmp/ nocase ascii wide
                        $string75_nanodump_offensive_tool_keyword = /ppl_medic_dll\./ nocase ascii wide
                        $string76_nanodump_offensive_tool_keyword = "prepare_ppl_command_line" nocase ascii wide
                        $string77_nanodump_offensive_tool_keyword = "print_shtinkering_crash_location" nocase ascii wide
                        $string78_nanodump_offensive_tool_keyword = /randomize_sw2_seed\.py/ nocase ascii wide
                        $string79_nanodump_offensive_tool_keyword = /restore_signature\.sh\s.{0,100}\.dmp/
                        $string80_nanodump_offensive_tool_keyword = "run_ppl_dump_exploit" nocase ascii wide
                        $string81_nanodump_offensive_tool_keyword = "run_ppl_medic_exploit" nocase ascii wide
                        $string82_nanodump_offensive_tool_keyword = "--seclogon-leak-local" nocase ascii wide
                        $string83_nanodump_offensive_tool_keyword = "--seclogon-leak-remote" nocase ascii wide
                        $string84_nanodump_offensive_tool_keyword = "set_rpc_callstack" nocase ascii wide
                        $string85_nanodump_offensive_tool_keyword = "set_svchost_callstack" nocase ascii wide
                        $string86_nanodump_offensive_tool_keyword = "set_wmi_callstack" nocase ascii wide
                        $string87_nanodump_offensive_tool_keyword = /source\/shtinkering\./ nocase ascii wide
                        $string88_nanodump_offensive_tool_keyword = "--spoof-callstack " nocase ascii wide
                        $string89_nanodump_offensive_tool_keyword = "SW2_GetSyscallNumber" nocase ascii wide
                        $string90_nanodump_offensive_tool_keyword = "SW2_PopulateSyscallList" nocase ascii wide
                        $string91_nanodump_offensive_tool_keyword = "SW2_RVA2VA" nocase ascii wide
                        $string92_nanodump_offensive_tool_keyword = "SW3_GetSyscallAddress" nocase ascii wide
                        $string93_nanodump_offensive_tool_keyword = "werfault_shtinkering" nocase ascii wide
                        $string94_nanodump_offensive_tool_keyword = "werfault_silent_process_exit" nocase ascii wide
                        $string95_nanodump_offensive_tool_keyword = "write_payload_dll_transacted" nocase ascii wide
                        $string96_nanodump_offensive_tool_keyword = "nanodump" nocase ascii wide
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