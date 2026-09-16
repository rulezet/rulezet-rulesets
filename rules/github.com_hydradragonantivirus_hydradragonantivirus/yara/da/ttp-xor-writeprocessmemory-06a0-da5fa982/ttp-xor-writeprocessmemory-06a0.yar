rule TTP_XOR_WriteProcessMemory_06a0 {
  strings:
    $key_06a0 = { 51 d2 [2] 63 f0 [2] 65 c5 [2] 4b c5 [2] 74 d9 }

  condition:
    any of them
}