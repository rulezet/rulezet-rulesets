rule TTP_XOR_WriteProcessMemory_8958 {
  strings:
    $key_8958 = { de 2a [2] ec 08 [2] ea 3d [2] c4 3d [2] fb 21 }

  condition:
    any of them
}