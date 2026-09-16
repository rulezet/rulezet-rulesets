rule TTP_XOR_WriteProcessMemory_bc85 {
  strings:
    $key_bc85 = { eb f7 [2] d9 d5 [2] df e0 [2] f1 e0 [2] ce fc }

  condition:
    any of them
}