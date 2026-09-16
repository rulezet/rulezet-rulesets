rule TTP_XOR_WriteProcessMemory_5d63 {
  strings:
    $key_5d63 = { 0a 11 [2] 38 33 [2] 3e 06 [2] 10 06 [2] 2f 1a }

  condition:
    any of them
}