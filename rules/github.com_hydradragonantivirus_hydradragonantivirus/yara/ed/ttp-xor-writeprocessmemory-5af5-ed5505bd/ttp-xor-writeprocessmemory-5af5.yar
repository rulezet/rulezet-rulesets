rule TTP_XOR_WriteProcessMemory_5af5 {
  strings:
    $key_5af5 = { 0d 87 [2] 3f a5 [2] 39 90 [2] 17 90 [2] 28 8c }

  condition:
    any of them
}