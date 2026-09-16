rule TTP_XOR_WriteProcessMemory_8f30 {
  strings:
    $key_8f30 = { d8 42 [2] ea 60 [2] ec 55 [2] c2 55 [2] fd 49 }

  condition:
    any of them
}