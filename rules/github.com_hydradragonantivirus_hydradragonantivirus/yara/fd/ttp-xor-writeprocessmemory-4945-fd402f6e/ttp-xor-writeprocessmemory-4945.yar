rule TTP_XOR_WriteProcessMemory_4945 {
  strings:
    $key_4945 = { 1e 37 [2] 2c 15 [2] 2a 20 [2] 04 20 [2] 3b 3c }

  condition:
    any of them
}