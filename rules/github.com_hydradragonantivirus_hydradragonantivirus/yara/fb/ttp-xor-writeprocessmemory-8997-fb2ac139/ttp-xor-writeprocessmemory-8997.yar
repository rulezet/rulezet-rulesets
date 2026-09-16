rule TTP_XOR_WriteProcessMemory_8997 {
  strings:
    $key_8997 = { de e5 [2] ec c7 [2] ea f2 [2] c4 f2 [2] fb ee }

  condition:
    any of them
}