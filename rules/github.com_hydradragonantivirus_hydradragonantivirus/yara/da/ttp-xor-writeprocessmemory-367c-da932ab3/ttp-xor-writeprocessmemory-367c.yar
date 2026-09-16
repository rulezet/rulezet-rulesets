rule TTP_XOR_WriteProcessMemory_367c {
  strings:
    $key_367c = { 61 0e [2] 53 2c [2] 55 19 [2] 7b 19 [2] 44 05 }

  condition:
    any of them
}