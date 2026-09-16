rule TTP_XOR_WriteProcessMemory_4462 {
  strings:
    $key_4462 = { 13 10 [2] 21 32 [2] 27 07 [2] 09 07 [2] 36 1b }

  condition:
    any of them
}