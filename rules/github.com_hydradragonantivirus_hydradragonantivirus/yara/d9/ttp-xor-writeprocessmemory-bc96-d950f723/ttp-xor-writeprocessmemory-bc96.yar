rule TTP_XOR_WriteProcessMemory_bc96 {
  strings:
    $key_bc96 = { eb e4 [2] d9 c6 [2] df f3 [2] f1 f3 [2] ce ef }

  condition:
    any of them
}