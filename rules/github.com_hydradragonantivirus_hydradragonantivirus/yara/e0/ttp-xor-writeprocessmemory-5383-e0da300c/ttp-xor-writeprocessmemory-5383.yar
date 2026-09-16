rule TTP_XOR_WriteProcessMemory_5383 {
  strings:
    $key_5383 = { 04 f1 [2] 36 d3 [2] 30 e6 [2] 1e e6 [2] 21 fa }

  condition:
    any of them
}