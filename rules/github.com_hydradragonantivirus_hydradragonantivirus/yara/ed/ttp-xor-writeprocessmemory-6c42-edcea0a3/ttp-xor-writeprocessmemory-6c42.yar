rule TTP_XOR_WriteProcessMemory_6c42 {
  strings:
    $key_6c42 = { 3b 30 [2] 09 12 [2] 0f 27 [2] 21 27 [2] 1e 3b }

  condition:
    any of them
}