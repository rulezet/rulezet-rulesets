rule APT28_IMPLANT_1_v6
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
      $XORopcodes_eax = { 35 (22 07 15 0e|56 d7 a7 0a) }
      $XORopcodes_others = { 81 (f1|f2|f3|f4|f5|f6|f7) (22 07 15 0e|56 d7 a7 0a) }

condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025) and any of them
}