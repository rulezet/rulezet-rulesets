rule TTP_XOR_WriteProcessMemory_895b {
  strings:
    $key_895b = { de 29 [2] ec 0b [2] ea 3e [2] c4 3e [2] fb 22 }

  condition:
    any of them
}