rule TTP_XOR_WriteProcessMemory_bc72 {
  strings:
    $key_bc72 = { eb 00 [2] d9 22 [2] df 17 [2] f1 17 [2] ce 0b }

  condition:
    any of them
}