rule TTP_XOR_WriteProcessMemory_bc31 {
  strings:
    $key_bc31 = { eb 43 [2] d9 61 [2] df 54 [2] f1 54 [2] ce 48 }

  condition:
    any of them
}