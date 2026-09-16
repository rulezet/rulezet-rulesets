rule TTP_XOR_WriteProcessMemory_0c55 {
  strings:
    $key_0c55 = { 5b 27 [2] 69 05 [2] 6f 30 [2] 41 30 [2] 7e 2c }

  condition:
    any of them
}