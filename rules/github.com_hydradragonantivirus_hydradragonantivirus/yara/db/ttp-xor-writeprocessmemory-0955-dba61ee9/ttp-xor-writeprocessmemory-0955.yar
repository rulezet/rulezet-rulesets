rule TTP_XOR_WriteProcessMemory_0955 {
  strings:
    $key_0955 = { 5e 27 [2] 6c 05 [2] 6a 30 [2] 44 30 [2] 7b 2c }

  condition:
    any of them
}