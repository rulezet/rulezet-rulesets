rule TTP_XOR_WriteProcessMemory_7d49 {
  strings:
    $key_7d49 = { 2a 3b [2] 18 19 [2] 1e 2c [2] 30 2c [2] 0f 30 }

  condition:
    any of them
}