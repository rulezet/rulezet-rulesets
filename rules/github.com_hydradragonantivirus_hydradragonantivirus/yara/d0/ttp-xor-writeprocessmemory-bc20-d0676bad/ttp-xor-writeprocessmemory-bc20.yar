rule TTP_XOR_WriteProcessMemory_bc20 {
  strings:
    $key_bc20 = { eb 52 [2] d9 70 [2] df 45 [2] f1 45 [2] ce 59 }

  condition:
    any of them
}