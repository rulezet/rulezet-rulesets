rule TTP_XOR_WriteProcessMemory_c1e9 {
  strings:
    $key_c1e9 = { 96 9b [2] a4 b9 [2] a2 8c [2] 8c 8c [2] b3 90 }

  condition:
    any of them
}