rule TTP_XOR_WriteProcessMemory_7bdc {
  strings:
    $key_7bdc = { 2c ae [2] 1e 8c [2] 18 b9 [2] 36 b9 [2] 09 a5 }

  condition:
    any of them
}