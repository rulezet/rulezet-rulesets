rule TTP_XOR_WriteProcessMemory_21f3 {
  strings:
    $key_21f3 = { 76 81 [2] 44 a3 [2] 42 96 [2] 6c 96 [2] 53 8a }

  condition:
    any of them
}