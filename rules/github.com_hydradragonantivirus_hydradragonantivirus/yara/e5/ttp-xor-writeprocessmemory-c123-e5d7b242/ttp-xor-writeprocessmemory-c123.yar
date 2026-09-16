rule TTP_XOR_WriteProcessMemory_c123 {
  strings:
    $key_c123 = { 96 51 [2] a4 73 [2] a2 46 [2] 8c 46 [2] b3 5a }

  condition:
    any of them
}