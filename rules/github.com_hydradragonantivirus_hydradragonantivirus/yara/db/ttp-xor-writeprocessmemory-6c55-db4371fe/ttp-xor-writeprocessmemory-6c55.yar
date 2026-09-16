rule TTP_XOR_WriteProcessMemory_6c55 {
  strings:
    $key_6c55 = { 3b 27 [2] 09 05 [2] 0f 30 [2] 21 30 [2] 1e 2c }

  condition:
    any of them
}