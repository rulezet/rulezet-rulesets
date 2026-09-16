rule TTP_XOR_WriteProcessMemory_8907 {
  strings:
    $key_8907 = { de 75 [2] ec 57 [2] ea 62 [2] c4 62 [2] fb 7e }

  condition:
    any of them
}