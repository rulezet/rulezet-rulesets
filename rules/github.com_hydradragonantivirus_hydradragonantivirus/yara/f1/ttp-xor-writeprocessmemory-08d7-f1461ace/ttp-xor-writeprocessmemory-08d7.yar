rule TTP_XOR_WriteProcessMemory_08d7 {
  strings:
    $key_08d7 = { 5f a5 [2] 6d 87 [2] 6b b2 [2] 45 b2 [2] 7a ae }

  condition:
    any of them
}