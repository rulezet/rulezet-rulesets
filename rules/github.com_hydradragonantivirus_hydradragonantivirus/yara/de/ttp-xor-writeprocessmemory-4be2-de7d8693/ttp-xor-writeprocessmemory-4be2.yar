rule TTP_XOR_WriteProcessMemory_4be2 {
  strings:
    $key_4be2 = { 1c 90 [2] 2e b2 [2] 28 87 [2] 06 87 [2] 39 9b }

  condition:
    any of them
}