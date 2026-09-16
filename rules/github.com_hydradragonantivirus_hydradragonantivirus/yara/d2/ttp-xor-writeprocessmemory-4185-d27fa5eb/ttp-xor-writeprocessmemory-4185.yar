rule TTP_XOR_WriteProcessMemory_4185 {
  strings:
    $key_4185 = { 16 f7 [2] 24 d5 [2] 22 e0 [2] 0c e0 [2] 33 fc }

  condition:
    any of them
}