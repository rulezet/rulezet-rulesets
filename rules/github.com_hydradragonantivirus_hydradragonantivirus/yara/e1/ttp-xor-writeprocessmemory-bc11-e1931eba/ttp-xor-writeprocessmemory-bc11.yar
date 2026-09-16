rule TTP_XOR_WriteProcessMemory_bc11 {
  strings:
    $key_bc11 = { eb 63 [2] d9 41 [2] df 74 [2] f1 74 [2] ce 68 }

  condition:
    any of them
}