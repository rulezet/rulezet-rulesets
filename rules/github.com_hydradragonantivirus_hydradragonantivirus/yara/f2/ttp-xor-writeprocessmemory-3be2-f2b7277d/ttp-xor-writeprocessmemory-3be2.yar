rule TTP_XOR_WriteProcessMemory_3be2 {
  strings:
    $key_3be2 = { 6c 90 [2] 5e b2 [2] 58 87 [2] 76 87 [2] 49 9b }

  condition:
    any of them
}