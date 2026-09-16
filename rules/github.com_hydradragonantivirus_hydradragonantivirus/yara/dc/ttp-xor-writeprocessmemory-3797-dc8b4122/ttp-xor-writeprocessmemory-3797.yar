rule TTP_XOR_WriteProcessMemory_3797 {
  strings:
    $key_3797 = { 60 e5 [2] 52 c7 [2] 54 f2 [2] 7a f2 [2] 45 ee }

  condition:
    any of them
}