rule APT30_Generic_C_RID2C17 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8667f635fe089c5e2c666b3fe22eaf3ff8590a69"
      hash2 = "0c4fcef3b583d0ffffc2b14b9297d3a4"
      hash3 = "37aee58655f5859e60ece6b249107b87"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "MYUSER32.dll" fullword ascii
      $s1 = "MYADVAPI32.dll" fullword ascii
      $s2 = "MYWSOCK32.dll" fullword ascii
      $s3 = "MYMSVCRT.dll" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}