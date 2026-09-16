rule TTP_XOR_WriteProcessMemory_7ff1 {
  strings:
    $key_7ff1 = { 28 83 [2] 1a a1 [2] 1c 94 [2] 32 94 [2] 0d 88 }

  condition:
    any of them
}