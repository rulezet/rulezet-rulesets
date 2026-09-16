rule TTP_XOR_WriteProcessMemory_c30d {
  strings:
    $key_c30d = { 94 7f [2] a6 5d [2] a0 68 [2] 8e 68 [2] b1 74 }

  condition:
    any of them
}