rule TTP_XOR_WriteProcessMemory_0297 {
  strings:
    $key_0297 = { 55 e5 [2] 67 c7 [2] 61 f2 [2] 4f f2 [2] 70 ee }

  condition:
    any of them
}