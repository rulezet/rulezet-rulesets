rule TTP_XOR_WriteProcessMemory_8fa2 {
  strings:
    $key_8fa2 = { d8 d0 [2] ea f2 [2] ec c7 [2] c2 c7 [2] fd db }

  condition:
    any of them
}