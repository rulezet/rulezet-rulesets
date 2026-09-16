rule TTP_XOR_WriteProcessMemory_c1f9 {
  strings:
    $key_c1f9 = { 96 8b [2] a4 a9 [2] a2 9c [2] 8c 9c [2] b3 80 }

  condition:
    any of them
}