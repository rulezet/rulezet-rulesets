rule TTP_XOR_WriteProcessMemory_c4f9 {
  strings:
    $key_c4f9 = { 93 8b [2] a1 a9 [2] a7 9c [2] 89 9c [2] b6 80 }

  condition:
    any of them
}