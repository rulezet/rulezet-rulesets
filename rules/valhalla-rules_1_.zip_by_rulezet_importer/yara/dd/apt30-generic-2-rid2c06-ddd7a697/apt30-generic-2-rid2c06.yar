rule APT30_Generic_2_RID2C06 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample - from many files"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:31:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7f11f5c9475240e5dd2eea7726c9229972cffc1f"
      hash2 = "94d3f91d1e50ecea729617729013c3d143bf2c3e"
      hash3 = "7e516ec04f28c76d67b8111ddfe58bbd628362cc"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%s\\%s\\KB985109.log" fullword
      $s1 = "%s\\%s\\KB989109.log" fullword
      $s2 = "Opera.exe" fullword wide
      $s3 = "%s:All online success on %u!" fullword
      $s4 = "%s:list online success on %u!" fullword
      $s5 = "%s:All online fail!" fullword
      $s6 = "Copyright Opera Software 1995-" wide
      $s7 = "%s:list online fail!" fullword
      $s8 = "OnlineTmp.txt" fullword
      $s9 = "Opera Internet Browser" fullword wide
      $s12 = "Opera Software" fullword wide
      $s15 = "Check lan have done!!!" fullword
      $s16 = "List End." fullword
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}