rule TTP_XOR_WriteProcessMemory_984c {
  strings:
    $key_984c = { cf 3e [2] fd 1c [2] fb 29 [2] d5 29 [2] ea 35 }

  condition:
    any of them
}