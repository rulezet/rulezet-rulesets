rule TTP_XOR_WriteProcessMemory_bc51 {
  strings:
    $key_bc51 = { eb 23 [2] d9 01 [2] df 34 [2] f1 34 [2] ce 28 }

  condition:
    any of them
}