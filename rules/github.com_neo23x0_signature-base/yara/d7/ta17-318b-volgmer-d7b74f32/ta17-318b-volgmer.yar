rule TA17_318B_volgmer {
   meta:
      description = "Malformed User Agent in Volgmer malware"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
      date = "2017-11-15"
      id = "20a7f64b-0fee-5235-ac91-2fc811497ac6"
   strings:
      $s = "Mozillar/"
   condition:
      ( uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550 ) and $s
}