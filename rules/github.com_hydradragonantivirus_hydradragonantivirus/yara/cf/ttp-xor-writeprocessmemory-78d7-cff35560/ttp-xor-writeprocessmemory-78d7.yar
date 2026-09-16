rule TTP_XOR_WriteProcessMemory_78d7 {
  strings:
    $key_78d7 = { 2f a5 [2] 1d 87 [2] 1b b2 [2] 35 b2 [2] 0a ae }

  condition:
    any of them
}