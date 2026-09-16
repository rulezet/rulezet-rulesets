rule TTP_XOR_WriteProcessMemory_4924 {
  strings:
    $key_4924 = { 1e 56 [2] 2c 74 [2] 2a 41 [2] 04 41 [2] 3b 5d }

  condition:
    any of them
}