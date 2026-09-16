rule PEiD_02330_Unnamed_Scrambler_1_1C____p0ke_ {
  meta:
    description = "[Unnamed Scrambler 1.1C -> p0ke]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 E4 53 56 33 C0 89 45 E4 89 45 E8 89 45 EC B8 C0 47 00 10 E8 4F F3 FF FF BE 5C 67 00 10 33 C0 55 68 D2 4A 00 10 64 FF 30 64 89 20 E8 EB DE FF FF E8 C6 F8 FF FF BA E0 4A 00 10 B8 CC 67 00 10 E8 5F F8 FF FF 8B D8 8B D6 8B C3 8B 0D CC 67 00 10 }

  condition:
    $a
}