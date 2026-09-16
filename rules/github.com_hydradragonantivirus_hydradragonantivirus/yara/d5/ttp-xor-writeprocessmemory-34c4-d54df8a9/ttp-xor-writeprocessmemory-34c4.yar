rule TTP_XOR_WriteProcessMemory_34c4 {
  strings:
    $key_34c4 = { 63 b6 [2] 51 94 [2] 57 a1 [2] 79 a1 [2] 46 bd }

  condition:
    any of them
}