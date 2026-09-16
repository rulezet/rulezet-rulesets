rule TTP_XOR_WriteProcessMemory_17a0 {
  strings:
    $key_17a0 = { 40 d2 [2] 72 f0 [2] 74 c5 [2] 5a c5 [2] 65 d9 }

  condition:
    any of them
}