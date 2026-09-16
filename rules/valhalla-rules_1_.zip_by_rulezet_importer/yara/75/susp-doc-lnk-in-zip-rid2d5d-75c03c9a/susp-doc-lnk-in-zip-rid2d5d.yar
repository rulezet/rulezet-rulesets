rule SUSP_DOC_LNK_in_ZIP_RID2D5D : DEMO FILE SUSP T1547_009 {
   meta:
      description = "Detects suspicious .doc.lnk file in ZIP archive"
      author = "Florian Roth"
      reference = "https://twitter.com/RedDrip7/status/1145877272945025029"
      date = "2019-07-02 10:28:41"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ea4f77cac557044e72a8e280372a2abe072f2ad98b5a4fbed4e2229e780173a"
      tags = "DEMO, FILE, SUSP, T1547_009"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".doc.lnk" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and 1 of them
}