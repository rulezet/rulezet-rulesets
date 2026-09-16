rule TTP_XOR_WriteProcessMemory_8f1b {
  strings:
    $key_8f1b = { d8 69 [2] ea 4b [2] ec 7e [2] c2 7e [2] fd 62 }

  condition:
    any of them
}