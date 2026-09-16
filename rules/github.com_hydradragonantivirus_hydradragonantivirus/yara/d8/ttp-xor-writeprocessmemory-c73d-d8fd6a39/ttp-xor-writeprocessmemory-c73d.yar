rule TTP_XOR_WriteProcessMemory_c73d {
  strings:
    $key_c73d = { 90 4f [2] a2 6d [2] a4 58 [2] 8a 58 [2] b5 44 }

  condition:
    any of them
}