rule TTP_XOR_WriteProcessMemory_8355 {
  strings:
    $key_8355 = { d4 27 [2] e6 05 [2] e0 30 [2] ce 30 [2] f1 2c }

  condition:
    any of them
}