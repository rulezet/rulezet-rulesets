rule TTP_XOR_WriteProcessMemory_4013 {
  strings:
    $key_4013 = { 17 61 [2] 25 43 [2] 23 76 [2] 0d 76 [2] 32 6a }

  condition:
    any of them
}