rule TTP_XOR_WriteProcessMemory_7ff0 {
  strings:
    $key_7ff0 = { 28 82 [2] 1a a0 [2] 1c 95 [2] 32 95 [2] 0d 89 }

  condition:
    any of them
}