rule TTP_XOR_WriteProcessMemory_8910 {
  strings:
    $key_8910 = { de 62 [2] ec 40 [2] ea 75 [2] c4 75 [2] fb 69 }

  condition:
    any of them
}