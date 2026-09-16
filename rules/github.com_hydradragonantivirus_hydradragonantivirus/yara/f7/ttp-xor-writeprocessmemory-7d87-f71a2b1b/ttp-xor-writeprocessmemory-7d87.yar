rule TTP_XOR_WriteProcessMemory_7d87 {
  strings:
    $key_7d87 = { 2a f5 [2] 18 d7 [2] 1e e2 [2] 30 e2 [2] 0f fe }

  condition:
    any of them
}