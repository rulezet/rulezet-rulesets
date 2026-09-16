import "pe"
import "math"
rule Ransom_Loader_Lockbit_V3 {
  meta:
    reference   = "506f3b12853375a1fbbf85c82ddf13341cf941c5acd4a39a51d6addf145a7a51"
    description = "Yara rule for the encrypted Lockbit 3.0 binary"

  strings:
    $indirectPEBAccess = {
      33 C0           40              C1 E0 06        8D 40 F0        64 8B 00        C3            }

    $Hex2BinUpperCaseSnippet = {
      66 83 F8 41        72 ??              66 83 F8 46        77 06              66 83 E8 37        EB ??            }

    $GetCommandLineBuffer = {
      E8 ?? FF FF FF        8B 40 10              8B 40 44              C3                  }

  condition:
    uint16(0) == 0x5A4D and
            math.entropy(0, filesize) >= 6.3
    and for any section in pe.sections:
    (
      (
        section.name != ".text"
        and section.characteristics & 0xff == 0x20          and
        (
          pe.entry_point >= section.raw_data_offset and
          pe.entry_point <= (section.raw_data_offset + section.raw_data_size)
        )
        and $indirectPEBAccess in (section.raw_data_offset..(section.raw_data_offset + section.raw_data_size))
        and $Hex2BinUpperCaseSnippet in (section.raw_data_offset..(section.raw_data_offset + section.raw_data_size))
        and $GetCommandLineBuffer in (section.raw_data_offset..(section.raw_data_offset + section.raw_data_size))
      )
    )
}