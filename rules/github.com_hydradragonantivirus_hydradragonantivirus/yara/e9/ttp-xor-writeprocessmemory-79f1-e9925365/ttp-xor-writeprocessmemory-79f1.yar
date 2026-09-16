rule TTP_XOR_WriteProcessMemory_79f1 {
  strings:
    $key_79f1 = { 2e 83 [2] 1c a1 [2] 1a 94 [2] 34 94 [2] 0b 88 }

  condition:
    any of them
}