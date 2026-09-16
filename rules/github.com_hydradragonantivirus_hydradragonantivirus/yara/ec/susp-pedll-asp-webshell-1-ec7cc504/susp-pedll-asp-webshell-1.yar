import "pe"
rule SUSP_PEDLL_ASP_WEBSHELL_1 {
  meta:
    author      = "@qutluch@infosec.exchange"
    description = "Rule to find .NET DLL ASP webshells."
    reference   = "https://ics-cert.kaspersky.com/publications/reports/2022/06/27/attacks-on-industrial-control-systems-using-shadowpad/"
    DaysofYARA  = "24/100"
    license     = "BSD-2-Clause"
    date        = "2024-01-31"
    version     = "1.0"
    hash        = "df79815b6fa50dfdd626be2d20a9e5d0741e4ceed4fd49da9f62ef4ecbc127a7"

  strings:
    $sa1 = "exec_code" wide
    $ha1 = {
                    02            6F [4]        28 [4]        74 [4]        7B [4]        26            02            28 [4]        72 [4]        28 [4]        02            6F [4]        28 [4]        26            02            6F [4]        28 [4]        74 [4]        7B [4]        26            02            6F [4]        28 [4]        74 [4]        7B          }

  condition:
    uint16(0) == 0x5A4D
    and (uint32(uint32(0x3C)) == 0x00004550)
    and uint16(uint32(0x3C) + 0x18) == 0x10b
    and pe.characteristics & pe.DLL
    and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0
    and uint32be(
      pe.rva_to_offset(
        uint32(
          pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address) + 8
        )
      )
    ) == 0x42534a42
    and all of them
}