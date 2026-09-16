rule TTP_XOR_WriteProcessMemory_79e6 {
  strings:
    $key_79e6 = { 2e 94 [2] 1c b6 [2] 1a 83 [2] 34 83 [2] 0b 9f }

  condition:
    any of them
}