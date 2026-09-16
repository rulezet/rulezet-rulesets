rule TTP_XOR_WriteProcessMemory_59e4 {
  strings:
    $key_59e4 = { 0e 96 [2] 3c b4 [2] 3a 81 [2] 14 81 [2] 2b 9d }

  condition:
    any of them
}