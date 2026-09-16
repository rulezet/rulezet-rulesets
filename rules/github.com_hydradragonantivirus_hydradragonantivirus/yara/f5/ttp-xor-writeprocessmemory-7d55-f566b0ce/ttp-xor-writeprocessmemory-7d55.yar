rule TTP_XOR_WriteProcessMemory_7d55 {
  strings:
    $key_7d55 = { 2a 27 [2] 18 05 [2] 1e 30 [2] 30 30 [2] 0f 2c }

  condition:
    any of them
}