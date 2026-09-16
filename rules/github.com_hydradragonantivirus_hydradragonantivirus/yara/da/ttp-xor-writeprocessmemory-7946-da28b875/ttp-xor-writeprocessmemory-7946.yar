rule TTP_XOR_WriteProcessMemory_7946 {
  strings:
    $key_7946 = { 2e 34 [2] 1c 16 [2] 1a 23 [2] 34 23 [2] 0b 3f }

  condition:
    any of them
}