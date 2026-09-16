rule TTP_XOR_WriteProcessMemory_7f43 {
  strings:
    $key_7f43 = { 28 31 [2] 1a 13 [2] 1c 26 [2] 32 26 [2] 0d 3a }

  condition:
    any of them
}