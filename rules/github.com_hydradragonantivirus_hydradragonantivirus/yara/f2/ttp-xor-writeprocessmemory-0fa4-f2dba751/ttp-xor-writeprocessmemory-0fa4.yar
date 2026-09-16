rule TTP_XOR_WriteProcessMemory_0fa4 {
  strings:
    $key_0fa4 = { 58 d6 [2] 6a f4 [2] 6c c1 [2] 42 c1 [2] 7d dd }

  condition:
    any of them
}