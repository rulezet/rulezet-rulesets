rule TTP_XOR_WriteProcessMemory_151c {
  strings:
    $key_151c = { 42 6e [2] 70 4c [2] 76 79 [2] 58 79 [2] 67 65 }

  condition:
    any of them
}