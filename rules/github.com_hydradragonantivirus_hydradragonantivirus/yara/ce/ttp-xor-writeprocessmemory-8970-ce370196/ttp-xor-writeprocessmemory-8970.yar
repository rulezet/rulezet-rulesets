rule TTP_XOR_WriteProcessMemory_8970 {
  strings:
    $key_8970 = { de 02 [2] ec 20 [2] ea 15 [2] c4 15 [2] fb 09 }

  condition:
    any of them
}