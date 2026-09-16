rule TTP_XOR_WriteProcessMemory_980b {
  strings:
    $key_980b = { cf 79 [2] fd 5b [2] fb 6e [2] d5 6e [2] ea 72 }

  condition:
    any of them
}