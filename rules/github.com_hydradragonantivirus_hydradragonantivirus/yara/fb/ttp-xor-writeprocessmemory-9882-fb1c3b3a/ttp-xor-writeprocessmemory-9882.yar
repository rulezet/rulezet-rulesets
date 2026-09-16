rule TTP_XOR_WriteProcessMemory_9882 {
  strings:
    $key_9882 = { cf f0 [2] fd d2 [2] fb e7 [2] d5 e7 [2] ea fb }

  condition:
    any of them
}