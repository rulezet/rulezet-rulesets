rule MAL_Chrysalis_Shellcode_Loader_Feb26 {
   meta:
      description = "Detects shellcode used to load Chrysalis backdoor, seen being used in the compromise of the infrastructure hosting Notepad++ by Chinese APT group Lotus Blossom"
      author = "X__Junior"
      date = "2026-02-02"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      hash = "e2e3d78437cf9d48c2b2264e44bb36bc2235834fc45bbb50b5d6867f336711e3"
      score = 80
      id = "4dce8370-19d3-579a-b1c7-7dd9fbe51ee6"
   strings:
      $op1 = { 8B C7 03 D7 83 E0 ?? 47 8A 4C 05 ?? 8A 04 13 02 C1 32 C1 2A C1 88 02 8B 55 ?? 3B FE 7C ?? 8B 5D ?? 8B 45 }
      $op2 = { 03 F8 8B 45 ?? 8B 50 ?? 85 C9 79 ?? 0F B7 C1 EB ?? 8D 41 ?? 03 C3 50 FF 75 ?? FF D2 89 07 85 C0 74 ?? 8B 4D ?? 46 }
   condition:
      1 of them
}