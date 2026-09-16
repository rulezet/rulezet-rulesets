rule TTP_XOR_WriteProcessMemory_5a63 {
  strings:
    $key_5a63 = { 0d 11 [2] 3f 33 [2] 39 06 [2] 17 06 [2] 28 1a }

  condition:
    any of them
}