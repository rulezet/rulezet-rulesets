rule TTP_XOR_WriteProcessMemory_8f9c {
  strings:
    $key_8f9c = { d8 ee [2] ea cc [2] ec f9 [2] c2 f9 [2] fd e5 }

  condition:
    any of them
}