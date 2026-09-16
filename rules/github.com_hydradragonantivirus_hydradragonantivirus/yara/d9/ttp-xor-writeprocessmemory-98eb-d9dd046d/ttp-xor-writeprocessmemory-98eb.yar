rule TTP_XOR_WriteProcessMemory_98eb {
  strings:
    $key_98eb = { cf 99 [2] fd bb [2] fb 8e [2] d5 8e [2] ea 92 }

  condition:
    any of them
}