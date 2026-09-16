rule TTP_XOR_WriteProcessMemory_b17d {
  strings:
    $key_b17d = { e6 0f [2] d4 2d [2] d2 18 [2] fc 18 [2] c3 04 }

  condition:
    any of them
}