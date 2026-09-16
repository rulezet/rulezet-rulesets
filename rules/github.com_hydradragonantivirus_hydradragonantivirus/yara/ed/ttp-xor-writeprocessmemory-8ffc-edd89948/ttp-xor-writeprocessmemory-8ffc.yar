rule TTP_XOR_WriteProcessMemory_8ffc {
  strings:
    $key_8ffc = { d8 8e [2] ea ac [2] ec 99 [2] c2 99 [2] fd 85 }

  condition:
    any of them
}