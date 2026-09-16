rule TTP_XOR_WriteProcessMemory_33b4 {
  strings:
    $key_33b4 = { 64 c6 [2] 56 e4 [2] 50 d1 [2] 7e d1 [2] 41 cd }

  condition:
    any of them
}