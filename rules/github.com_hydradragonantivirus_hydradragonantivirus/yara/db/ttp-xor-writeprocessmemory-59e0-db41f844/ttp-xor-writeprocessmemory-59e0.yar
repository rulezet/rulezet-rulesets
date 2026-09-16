rule TTP_XOR_WriteProcessMemory_59e0 {
  strings:
    $key_59e0 = { 0e 92 [2] 3c b0 [2] 3a 85 [2] 14 85 [2] 2b 99 }

  condition:
    any of them
}