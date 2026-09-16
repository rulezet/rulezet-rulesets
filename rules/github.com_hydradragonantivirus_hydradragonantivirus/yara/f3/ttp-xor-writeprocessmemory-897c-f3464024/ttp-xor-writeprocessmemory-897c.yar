rule TTP_XOR_WriteProcessMemory_897c {
  strings:
    $key_897c = { de 0e [2] ec 2c [2] ea 19 [2] c4 19 [2] fb 05 }

  condition:
    any of them
}