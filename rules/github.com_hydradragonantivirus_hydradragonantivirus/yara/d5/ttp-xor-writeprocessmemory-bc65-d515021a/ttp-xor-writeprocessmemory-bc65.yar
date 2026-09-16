rule TTP_XOR_WriteProcessMemory_bc65 {
  strings:
    $key_bc65 = { eb 17 [2] d9 35 [2] df 00 [2] f1 00 [2] ce 1c }

  condition:
    any of them
}