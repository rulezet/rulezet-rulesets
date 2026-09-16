rule TTP_XOR_WriteProcessMemory_8917 {
  strings:
    $key_8917 = { de 65 [2] ec 47 [2] ea 72 [2] c4 72 [2] fb 6e }

  condition:
    any of them
}