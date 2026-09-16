rule TTP_XOR_WriteProcessMemory_8940 {
  strings:
    $key_8940 = { de 32 [2] ec 10 [2] ea 25 [2] c4 25 [2] fb 39 }

  condition:
    any of them
}