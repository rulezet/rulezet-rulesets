rule TTP_XOR_WriteProcessMemory_51c4 {
  strings:
    $key_51c4 = { 06 b6 [2] 34 94 [2] 32 a1 [2] 1c a1 [2] 23 bd }

  condition:
    any of them
}