rule TTP_XOR_WriteProcessMemory_890b {
  strings:
    $key_890b = { de 79 [2] ec 5b [2] ea 6e [2] c4 6e [2] fb 72 }

  condition:
    any of them
}