rule TTP_XOR_WriteProcessMemory_7f63 {
  strings:
    $key_7f63 = { 28 11 [2] 1a 33 [2] 1c 06 [2] 32 06 [2] 0d 1a }

  condition:
    any of them
}