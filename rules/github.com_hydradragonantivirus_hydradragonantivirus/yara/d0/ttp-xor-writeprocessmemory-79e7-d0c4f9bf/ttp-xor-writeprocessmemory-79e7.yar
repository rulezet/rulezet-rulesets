rule TTP_XOR_WriteProcessMemory_79e7 {
  strings:
    $key_79e7 = { 2e 95 [2] 1c b7 [2] 1a 82 [2] 34 82 [2] 0b 9e }

  condition:
    any of them
}