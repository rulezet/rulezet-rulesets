rule TTP_XOR_WriteProcessMemory_8f4c {
  strings:
    $key_8f4c = { d8 3e [2] ea 1c [2] ec 29 [2] c2 29 [2] fd 35 }

  condition:
    any of them
}