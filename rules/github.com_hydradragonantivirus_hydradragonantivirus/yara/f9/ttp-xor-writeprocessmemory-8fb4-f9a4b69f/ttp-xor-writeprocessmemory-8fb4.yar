rule TTP_XOR_WriteProcessMemory_8fb4 {
  strings:
    $key_8fb4 = { d8 c6 [2] ea e4 [2] ec d1 [2] c2 d1 [2] fd cd }

  condition:
    any of them
}