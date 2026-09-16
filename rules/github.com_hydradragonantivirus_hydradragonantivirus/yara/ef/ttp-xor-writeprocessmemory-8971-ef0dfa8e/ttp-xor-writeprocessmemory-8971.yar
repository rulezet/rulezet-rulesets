rule TTP_XOR_WriteProcessMemory_8971 {
  strings:
    $key_8971 = { de 03 [2] ec 21 [2] ea 14 [2] c4 14 [2] fb 08 }

  condition:
    any of them
}