rule TTP_XOR_WriteProcessMemory_bc21 {
  strings:
    $key_bc21 = { eb 53 [2] d9 71 [2] df 44 [2] f1 44 [2] ce 58 }

  condition:
    any of them
}