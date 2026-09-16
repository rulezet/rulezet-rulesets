rule TTP_XOR_WriteProcessMemory_f5c4 {
  strings:
    $key_f5c4 = { a2 b6 [2] 90 94 [2] 96 a1 [2] b8 a1 [2] 87 bd }

  condition:
    any of them
}