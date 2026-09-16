rule TTP_XOR_WriteProcessMemory_4213 {
  strings:
    $key_4213 = { 15 61 [2] 27 43 [2] 21 76 [2] 0f 76 [2] 30 6a }

  condition:
    any of them
}