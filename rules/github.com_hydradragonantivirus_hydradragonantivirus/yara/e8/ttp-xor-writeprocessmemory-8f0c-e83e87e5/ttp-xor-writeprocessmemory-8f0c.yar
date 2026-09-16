rule TTP_XOR_WriteProcessMemory_8f0c {
  strings:
    $key_8f0c = { d8 7e [2] ea 5c [2] ec 69 [2] c2 69 [2] fd 75 }

  condition:
    any of them
}