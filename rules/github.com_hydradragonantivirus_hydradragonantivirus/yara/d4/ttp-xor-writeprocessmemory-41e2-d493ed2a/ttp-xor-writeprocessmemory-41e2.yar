rule TTP_XOR_WriteProcessMemory_41e2 {
  strings:
    $key_41e2 = { 16 90 [2] 24 b2 [2] 22 87 [2] 0c 87 [2] 33 9b }

  condition:
    any of them
}