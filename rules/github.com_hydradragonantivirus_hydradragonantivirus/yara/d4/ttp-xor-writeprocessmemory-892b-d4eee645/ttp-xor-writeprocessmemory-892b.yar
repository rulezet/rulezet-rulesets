rule TTP_XOR_WriteProcessMemory_892b {
  strings:
    $key_892b = { de 59 [2] ec 7b [2] ea 4e [2] c4 4e [2] fb 52 }

  condition:
    any of them
}