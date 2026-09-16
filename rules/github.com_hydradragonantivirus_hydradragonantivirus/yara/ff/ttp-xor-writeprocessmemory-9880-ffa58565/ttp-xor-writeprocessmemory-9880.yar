rule TTP_XOR_WriteProcessMemory_9880 {
  strings:
    $key_9880 = { cf f2 [2] fd d0 [2] fb e5 [2] d5 e5 [2] ea f9 }

  condition:
    any of them
}