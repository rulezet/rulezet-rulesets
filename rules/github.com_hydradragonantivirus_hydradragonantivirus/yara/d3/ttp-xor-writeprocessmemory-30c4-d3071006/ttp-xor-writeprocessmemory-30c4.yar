rule TTP_XOR_WriteProcessMemory_30c4 {
  strings:
    $key_30c4 = { 67 b6 [2] 55 94 [2] 53 a1 [2] 7d a1 [2] 42 bd }

  condition:
    any of them
}