rule TTP_XOR_WriteProcessMemory_8953 {
  strings:
    $key_8953 = { de 21 [2] ec 03 [2] ea 36 [2] c4 36 [2] fb 2a }

  condition:
    any of them
}