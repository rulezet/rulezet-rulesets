rule TTP_XOR_WriteProcessMemory_18d7 {
  strings:
    $key_18d7 = { 4f a5 [2] 7d 87 [2] 7b b2 [2] 55 b2 [2] 6a ae }

  condition:
    any of them
}