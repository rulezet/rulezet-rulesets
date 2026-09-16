rule TTP_XOR_WriteProcessMemory_8974 {
  strings:
    $key_8974 = { de 06 [2] ec 24 [2] ea 11 [2] c4 11 [2] fb 0d }

  condition:
    any of them
}