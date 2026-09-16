rule TTP_XOR_WriteProcessMemory_8963 {
  strings:
    $key_8963 = { de 11 [2] ec 33 [2] ea 06 [2] c4 06 [2] fb 1a }

  condition:
    any of them
}