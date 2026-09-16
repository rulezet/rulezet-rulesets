rule TTP_XOR_WriteProcessMemory_8f84 {
  strings:
    $key_8f84 = { d8 f6 [2] ea d4 [2] ec e1 [2] c2 e1 [2] fd fd }

  condition:
    any of them
}