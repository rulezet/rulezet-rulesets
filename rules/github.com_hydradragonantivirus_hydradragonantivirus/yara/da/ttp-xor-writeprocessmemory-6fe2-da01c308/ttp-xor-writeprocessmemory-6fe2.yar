rule TTP_XOR_WriteProcessMemory_6fe2 {
  strings:
    $key_6fe2 = { 38 90 [2] 0a b2 [2] 0c 87 [2] 22 87 [2] 1d 9b }

  condition:
    any of them
}