rule TTP_XOR_WriteProcessMemory_c13d {
  strings:
    $key_c13d = { 96 4f [2] a4 6d [2] a2 58 [2] 8c 58 [2] b3 44 }

  condition:
    any of them
}