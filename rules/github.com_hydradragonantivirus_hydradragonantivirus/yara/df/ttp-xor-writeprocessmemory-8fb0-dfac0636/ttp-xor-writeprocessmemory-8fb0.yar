rule TTP_XOR_WriteProcessMemory_8fb0 {
  strings:
    $key_8fb0 = { d8 c2 [2] ea e0 [2] ec d5 [2] c2 d5 [2] fd c9 }

  condition:
    any of them
}