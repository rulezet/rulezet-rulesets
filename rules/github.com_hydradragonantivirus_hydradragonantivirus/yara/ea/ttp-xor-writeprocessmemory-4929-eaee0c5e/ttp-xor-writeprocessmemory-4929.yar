rule TTP_XOR_WriteProcessMemory_4929 {
  strings:
    $key_4929 = { 1e 5b [2] 2c 79 [2] 2a 4c [2] 04 4c [2] 3b 50 }

  condition:
    any of them
}