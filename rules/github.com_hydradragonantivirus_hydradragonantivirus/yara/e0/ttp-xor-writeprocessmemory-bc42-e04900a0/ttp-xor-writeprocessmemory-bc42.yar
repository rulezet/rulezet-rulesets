rule TTP_XOR_WriteProcessMemory_bc42 {
  strings:
    $key_bc42 = { eb 30 [2] d9 12 [2] df 27 [2] f1 27 [2] ce 3b }

  condition:
    any of them
}