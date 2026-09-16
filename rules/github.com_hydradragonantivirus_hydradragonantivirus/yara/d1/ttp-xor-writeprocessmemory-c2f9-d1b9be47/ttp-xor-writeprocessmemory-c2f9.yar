rule TTP_XOR_WriteProcessMemory_c2f9 {
  strings:
    $key_c2f9 = { 95 8b [2] a7 a9 [2] a1 9c [2] 8f 9c [2] b0 80 }

  condition:
    any of them
}