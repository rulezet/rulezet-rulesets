rule TTP_XOR_WriteProcessMemory_1fe6 {
  strings:
    $key_1fe6 = { 48 94 [2] 7a b6 [2] 7c 83 [2] 52 83 [2] 6d 9f }

  condition:
    any of them
}