rule TTP_XOR_WriteProcessMemory_98a9 {
  strings:
    $key_98a9 = { cf db [2] fd f9 [2] fb cc [2] d5 cc [2] ea d0 }

  condition:
    any of them
}