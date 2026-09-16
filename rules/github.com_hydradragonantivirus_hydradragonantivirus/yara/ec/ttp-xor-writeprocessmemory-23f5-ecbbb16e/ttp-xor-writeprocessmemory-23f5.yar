rule TTP_XOR_WriteProcessMemory_23f5 {
  strings:
    $key_23f5 = { 74 87 [2] 46 a5 [2] 40 90 [2] 6e 90 [2] 51 8c }

  condition:
    any of them
}