rule TTP_XOR_WriteProcessMemory_c161 {
  strings:
    $key_c161 = { 96 13 [2] a4 31 [2] a2 04 [2] 8c 04 [2] b3 18 }

  condition:
    any of them
}