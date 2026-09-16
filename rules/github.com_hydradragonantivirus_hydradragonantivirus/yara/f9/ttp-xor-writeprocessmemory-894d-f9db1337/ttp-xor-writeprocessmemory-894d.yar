rule TTP_XOR_WriteProcessMemory_894d {
  strings:
    $key_894d = { de 3f [2] ec 1d [2] ea 28 [2] c4 28 [2] fb 34 }

  condition:
    any of them
}