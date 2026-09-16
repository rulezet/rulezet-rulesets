rule SUSP_DOC_LNK_in_ZIP {
   meta:
      description = "Detects suspicious .doc.lnk file in ZIP archive"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/RedDrip7/status/1145877272945025029"
      date = "2019-07-02"
      score = 50
      hash1 = "7ea4f77cac557044e72a8e280372a2abe072f2ad98b5a4fbed4e2229e780173a"
      id = "9c140d02-3b18-5faf-bb1d-2eb5c07a23dc"
   strings:
      $s1 = ".doc.lnk" fullword ascii
   condition:
      uint16(0) == 0x4b50 and 1 of them
}