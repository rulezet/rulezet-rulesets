rule TTP_XOR_WriteProcessMemory_6c02 {
  strings:
    $key_6c02 = { 3b 70 [2] 09 52 [2] 0f 67 [2] 21 67 [2] 1e 7b }

  condition:
    any of them
}