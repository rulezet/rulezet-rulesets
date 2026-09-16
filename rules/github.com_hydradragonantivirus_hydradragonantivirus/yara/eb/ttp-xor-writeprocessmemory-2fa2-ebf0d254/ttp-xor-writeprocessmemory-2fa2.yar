rule TTP_XOR_WriteProcessMemory_2fa2 {
  strings:
    $key_2fa2 = { 78 d0 [2] 4a f2 [2] 4c c7 [2] 62 c7 [2] 5d db }

  condition:
    any of them
}