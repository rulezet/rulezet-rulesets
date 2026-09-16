rule TTP_XOR_WriteProcessMemory_59e6 {
  strings:
    $key_59e6 = { 0e 94 [2] 3c b6 [2] 3a 83 [2] 14 83 [2] 2b 9f }

  condition:
    any of them
}