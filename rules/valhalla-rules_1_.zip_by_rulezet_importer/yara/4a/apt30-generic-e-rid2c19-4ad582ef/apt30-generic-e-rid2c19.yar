rule APT30_Generic_E_RID2C19 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1dbb584e19499e26398fb0a7aa2a01b7"
      hash2 = "572c9cd4388699347c0b2edb7c6f5e25"
      hash3 = "8ff473bedbcc77df2c49a91167b1abeb"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Nkfvtyvn}" ascii
      $s6 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}