rule TTP_XOR_WriteProcessMemory_8959 {
  strings:
    $key_8959 = { de 2b [2] ec 09 [2] ea 3c [2] c4 3c [2] fb 20 }

  condition:
    any of them
}