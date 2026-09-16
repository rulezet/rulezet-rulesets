rule TTP_XOR_WriteProcessMemory_3fe2 {
  strings:
    $key_3fe2 = { 68 90 [2] 5a b2 [2] 5c 87 [2] 72 87 [2] 4d 9b }

  condition:
    any of them
}