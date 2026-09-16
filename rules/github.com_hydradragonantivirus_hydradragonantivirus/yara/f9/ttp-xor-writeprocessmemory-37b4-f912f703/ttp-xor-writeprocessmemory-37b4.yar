rule TTP_XOR_WriteProcessMemory_37b4 {
  strings:
    $key_37b4 = { 60 c6 [2] 52 e4 [2] 54 d1 [2] 7a d1 [2] 45 cd }

  condition:
    any of them
}