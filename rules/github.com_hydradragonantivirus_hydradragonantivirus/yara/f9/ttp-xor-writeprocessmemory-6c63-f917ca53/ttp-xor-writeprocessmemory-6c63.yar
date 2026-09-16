rule TTP_XOR_WriteProcessMemory_6c63 {
  strings:
    $key_6c63 = { 3b 11 [2] 09 33 [2] 0f 06 [2] 21 06 [2] 1e 1a }

  condition:
    any of them
}