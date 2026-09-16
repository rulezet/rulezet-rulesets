rule TTP_XOR_WriteProcessMemory_8f3e {
  strings:
    $key_8f3e = { d8 4c [2] ea 6e [2] ec 5b [2] c2 5b [2] fd 47 }

  condition:
    any of them
}