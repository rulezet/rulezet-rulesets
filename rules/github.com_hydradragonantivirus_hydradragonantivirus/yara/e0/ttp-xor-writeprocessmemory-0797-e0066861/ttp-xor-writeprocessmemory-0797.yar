rule TTP_XOR_WriteProcessMemory_0797 {
  strings:
    $key_0797 = { 50 e5 [2] 62 c7 [2] 64 f2 [2] 4a f2 [2] 75 ee }

  condition:
    any of them
}