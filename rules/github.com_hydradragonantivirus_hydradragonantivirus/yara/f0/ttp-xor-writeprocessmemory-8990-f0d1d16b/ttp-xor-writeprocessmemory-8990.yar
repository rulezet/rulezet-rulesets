rule TTP_XOR_WriteProcessMemory_8990 {
  strings:
    $key_8990 = { de e2 [2] ec c0 [2] ea f5 [2] c4 f5 [2] fb e9 }

  condition:
    any of them
}