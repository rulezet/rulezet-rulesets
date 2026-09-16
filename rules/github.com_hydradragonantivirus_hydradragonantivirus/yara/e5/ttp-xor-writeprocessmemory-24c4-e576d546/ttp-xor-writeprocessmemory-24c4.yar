rule TTP_XOR_WriteProcessMemory_24c4 {
  strings:
    $key_24c4 = { 73 b6 [2] 41 94 [2] 47 a1 [2] 69 a1 [2] 56 bd }

  condition:
    any of them
}