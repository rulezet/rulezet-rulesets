rule TTP_XOR_WriteProcessMemory_bc46 {
  strings:
    $key_bc46 = { eb 34 [2] d9 16 [2] df 23 [2] f1 23 [2] ce 3f }

  condition:
    any of them
}