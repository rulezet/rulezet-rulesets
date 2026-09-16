rule TTP_XOR_WriteProcessMemory_bc66 {
  strings:
    $key_bc66 = { eb 14 [2] d9 36 [2] df 03 [2] f1 03 [2] ce 1f }

  condition:
    any of them
}