rule TTP_XOR_WriteProcessMemory_1385 {
  strings:
    $key_1385 = { 44 f7 [2] 76 d5 [2] 70 e0 [2] 5e e0 [2] 61 fc }

  condition:
    any of them
}