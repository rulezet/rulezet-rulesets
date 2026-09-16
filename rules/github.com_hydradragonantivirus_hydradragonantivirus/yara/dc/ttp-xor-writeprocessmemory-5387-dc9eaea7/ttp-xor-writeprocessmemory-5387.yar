rule TTP_XOR_WriteProcessMemory_5387 {
  strings:
    $key_5387 = { 04 f5 [2] 36 d7 [2] 30 e2 [2] 1e e2 [2] 21 fe }

  condition:
    any of them
}