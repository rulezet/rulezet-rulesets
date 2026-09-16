rule TTP_XOR_WriteProcessMemory_8994 {
  strings:
    $key_8994 = { de e6 [2] ec c4 [2] ea f1 [2] c4 f1 [2] fb ed }

  condition:
    any of them
}