rule TTP_XOR_WriteProcessMemory_6663 {
  strings:
    $key_6663 = { 31 11 [2] 03 33 [2] 05 06 [2] 2b 06 [2] 14 1a }

  condition:
    any of them
}