rule TTP_XOR_WriteProcessMemory_1fe2 {
  strings:
    $key_1fe2 = { 48 90 [2] 7a b2 [2] 7c 87 [2] 52 87 [2] 6d 9b }

  condition:
    any of them
}