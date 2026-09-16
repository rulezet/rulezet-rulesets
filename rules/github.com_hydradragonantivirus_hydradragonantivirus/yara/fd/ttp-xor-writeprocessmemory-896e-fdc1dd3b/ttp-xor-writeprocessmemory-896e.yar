rule TTP_XOR_WriteProcessMemory_896e {
  strings:
    $key_896e = { de 1c [2] ec 3e [2] ea 0b [2] c4 0b [2] fb 17 }

  condition:
    any of them
}