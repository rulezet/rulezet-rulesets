rule TTP_XOR_WriteProcessMemory_bc76 {
  strings:
    $key_bc76 = { eb 04 [2] d9 26 [2] df 13 [2] f1 13 [2] ce 0f }

  condition:
    any of them
}