rule TTP_XOR_WriteProcessMemory_0fd4 {
  strings:
    $key_0fd4 = { 58 a6 [2] 6a 84 [2] 6c b1 [2] 42 b1 [2] 7d ad }

  condition:
    any of them
}