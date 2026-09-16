rule TTP_XOR_WriteProcessMemory_6f63 {
  strings:
    $key_6f63 = { 38 11 [2] 0a 33 [2] 0c 06 [2] 22 06 [2] 1d 1a }

  condition:
    any of them
}