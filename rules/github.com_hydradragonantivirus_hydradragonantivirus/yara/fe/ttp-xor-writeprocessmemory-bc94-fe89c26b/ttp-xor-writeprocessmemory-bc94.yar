rule TTP_XOR_WriteProcessMemory_bc94 {
  strings:
    $key_bc94 = { eb e6 [2] d9 c4 [2] df f1 [2] f1 f1 [2] ce ed }

  condition:
    any of them
}