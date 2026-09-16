rule TTP_XOR_WriteProcessMemory_8941 {
  strings:
    $key_8941 = { de 33 [2] ec 11 [2] ea 24 [2] c4 24 [2] fb 38 }

  condition:
    any of them
}