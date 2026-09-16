rule TTP_XOR_WriteProcessMemory_a573 {
  strings:
    $key_a573 = { f2 01 [2] c0 23 [2] c6 16 [2] e8 16 [2] d7 0a }

  condition:
    any of them
}