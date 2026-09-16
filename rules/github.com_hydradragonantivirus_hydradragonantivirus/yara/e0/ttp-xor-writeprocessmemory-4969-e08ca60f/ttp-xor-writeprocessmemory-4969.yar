rule TTP_XOR_WriteProcessMemory_4969 {
  strings:
    $key_4969 = { 1e 1b [2] 2c 39 [2] 2a 0c [2] 04 0c [2] 3b 10 }

  condition:
    any of them
}