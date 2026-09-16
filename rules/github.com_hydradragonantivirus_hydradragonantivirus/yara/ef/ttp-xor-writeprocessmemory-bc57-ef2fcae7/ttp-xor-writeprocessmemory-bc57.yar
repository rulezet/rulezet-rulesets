rule TTP_XOR_WriteProcessMemory_bc57 {
  strings:
    $key_bc57 = { eb 25 [2] d9 07 [2] df 32 [2] f1 32 [2] ce 2e }

  condition:
    any of them
}