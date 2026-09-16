rule TTP_XOR_WriteProcessMemory_0290 {
  strings:
    $key_0290 = { 55 e2 [2] 67 c0 [2] 61 f5 [2] 4f f5 [2] 70 e9 }

  condition:
    any of them
}