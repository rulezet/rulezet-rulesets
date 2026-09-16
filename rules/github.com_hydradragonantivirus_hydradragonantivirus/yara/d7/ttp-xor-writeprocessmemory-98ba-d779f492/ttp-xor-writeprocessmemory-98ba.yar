rule TTP_XOR_WriteProcessMemory_98ba {
  strings:
    $key_98ba = { cf c8 [2] fd ea [2] fb df [2] d5 df [2] ea c3 }

  condition:
    any of them
}