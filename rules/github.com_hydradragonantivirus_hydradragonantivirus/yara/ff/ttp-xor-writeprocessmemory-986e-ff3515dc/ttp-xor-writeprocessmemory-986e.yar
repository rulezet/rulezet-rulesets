rule TTP_XOR_WriteProcessMemory_986e {
  strings:
    $key_986e = { cf 1c [2] fd 3e [2] fb 0b [2] d5 0b [2] ea 17 }

  condition:
    any of them
}