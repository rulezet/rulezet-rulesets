rule TTP_XOR_WriteProcessMemory_8949 {
  strings:
    $key_8949 = { de 3b [2] ec 19 [2] ea 2c [2] c4 2c [2] fb 30 }

  condition:
    any of them
}