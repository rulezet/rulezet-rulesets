rule TTP_XOR_WriteProcessMemory_277c {
  strings:
    $key_277c = { 70 0e [2] 42 2c [2] 44 19 [2] 6a 19 [2] 55 05 }

  condition:
    any of them
}