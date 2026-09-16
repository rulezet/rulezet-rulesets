rule TTP_XOR_WriteProcessMemory_1185 {
  strings:
    $key_1185 = { 46 f7 [2] 74 d5 [2] 72 e0 [2] 5c e0 [2] 63 fc }

  condition:
    any of them
}