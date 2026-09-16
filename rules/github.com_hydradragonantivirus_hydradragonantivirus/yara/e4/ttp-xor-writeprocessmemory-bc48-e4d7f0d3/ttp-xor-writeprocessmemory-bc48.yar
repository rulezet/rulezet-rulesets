rule TTP_XOR_WriteProcessMemory_bc48 {
  strings:
    $key_bc48 = { eb 3a [2] d9 18 [2] df 2d [2] f1 2d [2] ce 31 }

  condition:
    any of them
}