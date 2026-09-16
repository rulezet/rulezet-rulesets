rule TTP_XOR_WriteProcessMemory_8928 {
  strings:
    $key_8928 = { de 5a [2] ec 78 [2] ea 4d [2] c4 4d [2] fb 51 }

  condition:
    any of them
}