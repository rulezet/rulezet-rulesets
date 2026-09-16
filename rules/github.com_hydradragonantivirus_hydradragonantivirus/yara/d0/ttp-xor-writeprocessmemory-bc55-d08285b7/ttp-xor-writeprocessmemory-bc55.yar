rule TTP_XOR_WriteProcessMemory_bc55 {
  strings:
    $key_bc55 = { eb 27 [2] d9 05 [2] df 30 [2] f1 30 [2] ce 2c }

  condition:
    any of them
}