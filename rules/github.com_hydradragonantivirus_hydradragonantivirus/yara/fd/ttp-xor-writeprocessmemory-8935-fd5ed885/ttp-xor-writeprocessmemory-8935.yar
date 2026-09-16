rule TTP_XOR_WriteProcessMemory_8935 {
  strings:
    $key_8935 = { de 47 [2] ec 65 [2] ea 50 [2] c4 50 [2] fb 4c }

  condition:
    any of them
}