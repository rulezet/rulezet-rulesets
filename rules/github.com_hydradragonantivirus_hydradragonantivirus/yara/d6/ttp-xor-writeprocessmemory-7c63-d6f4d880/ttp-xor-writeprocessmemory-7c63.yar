rule TTP_XOR_WriteProcessMemory_7c63 {
  strings:
    $key_7c63 = { 2b 11 [2] 19 33 [2] 1f 06 [2] 31 06 [2] 0e 1a }

  condition:
    any of them
}