rule TTP_XOR_WriteProcessMemory_8916 {
  strings:
    $key_8916 = { de 64 [2] ec 46 [2] ea 73 [2] c4 73 [2] fb 6f }

  condition:
    any of them
}