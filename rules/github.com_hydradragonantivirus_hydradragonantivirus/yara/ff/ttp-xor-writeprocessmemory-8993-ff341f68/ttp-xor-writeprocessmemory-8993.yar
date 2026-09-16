rule TTP_XOR_WriteProcessMemory_8993 {
  strings:
    $key_8993 = { de e1 [2] ec c3 [2] ea f6 [2] c4 f6 [2] fb ea }

  condition:
    any of them
}