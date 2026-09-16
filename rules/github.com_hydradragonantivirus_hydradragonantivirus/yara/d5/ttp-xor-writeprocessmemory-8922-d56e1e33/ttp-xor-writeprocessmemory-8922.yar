rule TTP_XOR_WriteProcessMemory_8922 {
  strings:
    $key_8922 = { de 50 [2] ec 72 [2] ea 47 [2] c4 47 [2] fb 5b }

  condition:
    any of them
}