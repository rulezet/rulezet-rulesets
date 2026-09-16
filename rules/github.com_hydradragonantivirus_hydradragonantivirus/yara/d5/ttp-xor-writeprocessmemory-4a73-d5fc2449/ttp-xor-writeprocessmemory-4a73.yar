rule TTP_XOR_WriteProcessMemory_4a73 {
  strings:
    $key_4a73 = { 1d 01 [2] 2f 23 [2] 29 16 [2] 07 16 [2] 38 0a }

  condition:
    any of them
}