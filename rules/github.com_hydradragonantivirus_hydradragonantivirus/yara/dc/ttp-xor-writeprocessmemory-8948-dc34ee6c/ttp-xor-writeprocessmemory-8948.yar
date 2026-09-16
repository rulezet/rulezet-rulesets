rule TTP_XOR_WriteProcessMemory_8948 {
  strings:
    $key_8948 = { de 3a [2] ec 18 [2] ea 2d [2] c4 2d [2] fb 31 }

  condition:
    any of them
}