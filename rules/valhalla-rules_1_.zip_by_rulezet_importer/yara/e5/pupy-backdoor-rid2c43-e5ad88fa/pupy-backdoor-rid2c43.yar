import "pe"
rule Pupy_Backdoor_RID2C43 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Pupy backdoor"
      author = "Florian Roth"
      reference = "https://github.com/n1nj4sec/pupy-binaries"
      date = "2017-08-11 09:41:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ae93714203c7ab4ab73f2ad8364819d16644c7649ea04f483b46924bd5bc0153"
      hash2 = "83380f351214c3bd2c8e62430f70f8f90d11c831695027f329af04806b9f8ea4"
      hash3 = "90757c1ae9597bea39bb52a38fb3d497358a2499c92c7636d71b95ec973186cc"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "reflectively inject a dll into a process." fullword ascii
      $x2 = "ld_preload_inject_dll(cmdline, dll_buffer, hook_exit) -> pid" fullword ascii
      $x3 = "LD_PRELOAD=%s HOOK_EXIT=%d CLEANUP=%d exec %s 1>/dev/null 2>/dev/null" fullword ascii
      $x4 = "reflective_inject_dll" fullword ascii
      $x5 = "ld_preload_inject_dll" fullword ascii
      $x6 = "get_pupy_config() -> string" fullword ascii
      $x7 = "[INJECT] inject_dll. OpenProcess failed." fullword ascii
      $x8 = "reflective_inject_dll" fullword ascii
      $x9 = "reflective_inject_dll(pid, dll_buffer, isRemoteProcess64bits)" fullword ascii
      $x10 = "linux_inject_main" fullword ascii
   condition: 
      ( ( uint16 ( 0 ) == 0x457f or uint16 ( 0 ) == 0x5a4d ) and filesize < 7000KB and 1 of them ) or 3 of them or ( uint16 ( 0 ) == 0x5a4d and pe.imphash ( ) == "84a69bce2ff6d9f866b7ae63bd70b163" )
}