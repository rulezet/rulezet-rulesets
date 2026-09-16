rule TTP_XOR_WriteProcessMemory_987e {
  strings:
    $key_987e = { cf 0c [2] fd 2e [2] fb 1b [2] d5 1b [2] ea 07 }

  condition:
    any of them
}