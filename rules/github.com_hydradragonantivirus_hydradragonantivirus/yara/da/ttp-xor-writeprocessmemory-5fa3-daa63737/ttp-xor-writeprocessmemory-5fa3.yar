rule TTP_XOR_WriteProcessMemory_5fa3 {
  strings:
    $key_5fa3 = { 08 d1 [2] 3a f3 [2] 3c c6 [2] 12 c6 [2] 2d da }

  condition:
    any of them
}