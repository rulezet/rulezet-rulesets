rule TTP_XOR_WriteProcessMemory_cea2 {
  strings:
    $key_cea2 = { 99 d0 [2] ab f2 [2] ad c7 [2] 83 c7 [2] bc db }

  condition:
    any of them
}