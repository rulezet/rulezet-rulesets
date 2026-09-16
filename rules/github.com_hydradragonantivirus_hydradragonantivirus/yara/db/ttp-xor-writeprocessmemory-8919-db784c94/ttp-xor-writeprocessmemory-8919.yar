rule TTP_XOR_WriteProcessMemory_8919 {
  strings:
    $key_8919 = { de 6b [2] ec 49 [2] ea 7c [2] c4 7c [2] fb 60 }

  condition:
    any of them
}