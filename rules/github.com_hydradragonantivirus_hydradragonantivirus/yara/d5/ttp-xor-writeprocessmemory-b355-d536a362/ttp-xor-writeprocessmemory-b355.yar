rule TTP_XOR_WriteProcessMemory_b355 {
  strings:
    $key_b355 = { e4 27 [2] d6 05 [2] d0 30 [2] fe 30 [2] c1 2c }

  condition:
    any of them
}