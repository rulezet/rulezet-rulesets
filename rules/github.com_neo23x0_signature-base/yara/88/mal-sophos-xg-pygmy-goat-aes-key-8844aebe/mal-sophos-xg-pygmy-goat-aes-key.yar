rule MAL_Sophos_XG_Pygmy_Goat_AES_Key {
   meta:
      description = "Detects Pygmy Goat - a native x86-32 ELF shared object that was discovered on Sophos XG firewall devices, providing backdoor access to the device. This detection rule is based on the Pygmy Goat AES key built on the stack or in data"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/pygmy-goat/ncsc-mar-pygmy-goat.pdf"
      author = "NCSC"
      date = "2024-10-22"
      score = 75
      hash1 = "71f70d61af00542b2e9ad64abd2dda7e437536ff"
      id = "62be3f4f-b435-54b2-b596-4ad01606edb8"
   strings:
      $dword_1 = { 59 4b 6e 77 }
      $dword_2 = { 51 6a 6d 41 }
      $dword_3 = { 54 62 41 6e }
      $dword_4 = { 52 6f 5a 6d }
      $dword_5 = { 30 66 47 37 }
      $dword_6 = { 55 5a 57 62 }
      $dword_7 = { 32 59 55 78 }
      $dword_8 = { 55 51 50 77 }
   condition:
      uint32(0) == 0x464c457f and all of them
            and filesize < 4MB
}