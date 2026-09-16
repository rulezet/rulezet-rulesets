rule TTP_XOR_WriteProcessMemory_4c63 {
  strings:
    $key_4c63 = { 1b 11 [2] 29 33 [2] 2f 06 [2] 01 06 [2] 3e 1a }

  condition:
    any of them
}