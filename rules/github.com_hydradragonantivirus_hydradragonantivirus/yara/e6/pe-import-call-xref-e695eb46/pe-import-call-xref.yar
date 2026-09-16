import "pe"
rule PE_import_call_xref {
  meta:
    author      = "@captainGeech42"
    description = "Look at PE x86 function call and validate the right import is called."
    date        = "2024-01-07"
    version     = "1"
    DaysofYARA  = "7/100"
    hash        = "6d0794f5e7ddac69d10c68ec0c6ae3744a1886bec4917e376b7d3a6078d1a410"

  strings:
    $c1 = {
            57
            6a 03
            57
            57
            ff 75 ??
            ff 75 ??
            ff 35 00 [3]
            ff 15
                }

  condition:
    uint16(0) == 0x5a4d and
    uint32(uint32(0x3c)) == 0x00004550 and
    for any imp in pe.import_details: (
      imp.library_name == "WININET.dll" and
      for any func in imp.functions: (
        func.name == "InternetConnectA" and
        uint32(@c1 + !c1) & 0xffffff == func.rva
      )
    )
}