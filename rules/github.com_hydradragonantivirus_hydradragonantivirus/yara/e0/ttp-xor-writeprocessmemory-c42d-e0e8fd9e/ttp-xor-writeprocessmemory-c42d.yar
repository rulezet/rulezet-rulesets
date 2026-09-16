rule TTP_XOR_WriteProcessMemory_c42d {
  strings:
    $key_c42d = { 93 5f [2] a1 7d [2] a7 48 [2] 89 48 [2] b6 54 }

  condition:
    any of them
}