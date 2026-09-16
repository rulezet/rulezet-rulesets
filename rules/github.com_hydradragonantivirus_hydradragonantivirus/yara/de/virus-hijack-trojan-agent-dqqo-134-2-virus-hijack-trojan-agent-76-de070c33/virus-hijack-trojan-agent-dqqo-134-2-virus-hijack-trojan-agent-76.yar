import "pe"
rule _Virus_Hijack_Trojan_Agent_DQQO_134_2_Virus_Hijack_Trojan_Agent__76 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.Agent.DQQO_134_2.vir, Virus.Hijack_Trojan.Agent.DQQO_137_2.vir, Virus.Hijack_Trojan.Agent.DQQO_148_2.vir, Virus.Hijack_Trojan.Agent.DQQO_149_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "233acbe374b48afd227cb3a66327ab57acef36d3ca74de14ad5a871e31b71985"
    hash2       = "de59f09ea79ba84c3de61e5fba25d0334d6dbe5db4101e33efa33a4faa2161fe"
    hash3       = "f876f08dc71f0d5a1d3b66672d44c4078017086f1b0aeeb88f3f362585e2183f"
    hash4       = "ddeb383f016bf5f7fda9010546a474a44464e36d7c5ca8e9c9e2db744657ac9f"

  strings:
    $s1  = "Unknown macro.'Unable to execute the external program.*Unable to get a list of running processes.*Missing separator character af" wide
    $s2  = "Assert Failed!I has encountered a fatal crash as a result of: Unable to execute DLLCall." fullword wide
    $s3  = "0Incorrect number of parameters in function call.'\"ReDim\" used without an array variable.>Illegal text at the end of statement" wide
    $s4  = " supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cd" wide
    $s5  = " has detected the stack has become corrupt." fullword wide
    $s6  = "Unable to access RunAs API." fullword wide
    $s7  = ">\"Select\" statement is missing \"EndSelect\" or \"Case\" statement.+\"If\" statements must have a \"Then\" keyword. Badly form" wide
    $s8  = "Missing operator in expression.\"Unbalanced brackets in expression." fullword wide
    $s9  = "AVector: back(): Out of bounds." fullword ascii
    $s10 = "Invalid file handle used." fullword wide
    $s11 = "Obsolete function/parameter.-Invalid Exitcode (reserved for internal use)." fullword wide
    $s12 = "Badly formated Enum statement!Badly formated variable or macro.3This keyword cannot be used after a \"Then\" keyword." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "fa2ce92b03d6ad0da8b5b4c269fef40a" and (8 of them)
    ) or (all of them)
}