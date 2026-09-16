rule TTP_XOR_WriteProcessMemory_4965 {
  strings:
    $key_4965 = { 1e 17 [2] 2c 35 [2] 2a 00 [2] 04 00 [2] 3b 1c }

  condition:
    any of them
}