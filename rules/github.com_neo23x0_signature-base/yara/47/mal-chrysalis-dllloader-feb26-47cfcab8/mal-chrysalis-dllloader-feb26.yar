rule MAL_Chrysalis_DllLoader_Feb26 {
   meta:
      description = "Detects DLL used to load Chrysalis backdoor, seen being used in the compromise of the infrastructure hosting Notepad++ by Chinese APT group Lotus Blossom"
      author = "X__Junior"
      date = "2026-02-02"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      hash = "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad"
      score = 80
      id = "a2bf8cde-36a5-565d-9257-f1a4b2d67adc"
   strings:
      $op1 = { 33 D2 8B C1 F7 F6 0F B6 C1 03 55 ?? 6B C0 ?? 32 02 88 04 0F 41 83 F9 ?? 72 }
      $op2 = { 0F B6 04 31 41 33 C2 69 D0 ?? ?? ?? ?? 3B CB 72 }
   condition:
      uint16(0) == 0x5a4d and all of them
}