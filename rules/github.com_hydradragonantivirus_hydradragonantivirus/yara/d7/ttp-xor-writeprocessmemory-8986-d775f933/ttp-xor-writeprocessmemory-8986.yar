rule TTP_XOR_WriteProcessMemory_8986 {
  strings:
    $key_8986 = { de f4 [2] ec d6 [2] ea e3 [2] c4 e3 [2] fb ff }

  condition:
    any of them
}