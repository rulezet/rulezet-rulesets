rule TTP_XOR_WriteProcessMemory_21c4 {
  strings:
    $key_21c4 = { 76 b6 [2] 44 94 [2] 42 a1 [2] 6c a1 [2] 53 bd }

  condition:
    any of them
}