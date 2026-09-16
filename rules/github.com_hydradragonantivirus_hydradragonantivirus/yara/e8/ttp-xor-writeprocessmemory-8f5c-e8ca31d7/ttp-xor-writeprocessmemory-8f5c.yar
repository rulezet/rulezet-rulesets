rule TTP_XOR_WriteProcessMemory_8f5c {
  strings:
    $key_8f5c = { d8 2e [2] ea 0c [2] ec 39 [2] c2 39 [2] fd 25 }

  condition:
    any of them
}