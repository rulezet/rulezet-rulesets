rule TTP_XOR_WriteProcessMemory_3313 {
  strings:
    $key_3313 = { 64 61 [2] 56 43 [2] 50 76 [2] 7e 76 [2] 41 6a }

  condition:
    any of them
}