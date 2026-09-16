rule TTP_XOR_WriteProcessMemory_efa7 {
  strings:
    $key_efa7 = { b8 d5 [2] 8a f7 [2] 8c c2 [2] a2 c2 [2] 9d de }

  condition:
    any of them
}