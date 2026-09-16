rule TTP_XOR_WriteProcessMemory_c17d {
  strings:
    $key_c17d = { 96 0f [2] a4 2d [2] a2 18 [2] 8c 18 [2] b3 04 }

  condition:
    any of them
}