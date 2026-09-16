rule TTP_XOR_WriteProcessMemory_3fa2 {
  strings:
    $key_3fa2 = { 68 d0 [2] 5a f2 [2] 5c c7 [2] 72 c7 [2] 4d db }

  condition:
    any of them
}