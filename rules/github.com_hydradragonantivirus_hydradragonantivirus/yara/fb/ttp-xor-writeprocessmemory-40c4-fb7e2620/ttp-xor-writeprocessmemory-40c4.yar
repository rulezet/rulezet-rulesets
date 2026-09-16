rule TTP_XOR_WriteProcessMemory_40c4 {
  strings:
    $key_40c4 = { 17 b6 [2] 25 94 [2] 23 a1 [2] 0d a1 [2] 32 bd }

  condition:
    any of them
}