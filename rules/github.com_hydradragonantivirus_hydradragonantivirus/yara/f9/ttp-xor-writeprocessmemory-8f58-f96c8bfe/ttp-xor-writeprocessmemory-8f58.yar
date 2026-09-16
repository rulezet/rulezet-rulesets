rule TTP_XOR_WriteProcessMemory_8f58 {
  strings:
    $key_8f58 = { d8 2a [2] ea 08 [2] ec 3d [2] c2 3d [2] fd 21 }

  condition:
    any of them
}