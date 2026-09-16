rule TTP_XOR_WriteProcessMemory_8f3d {
  strings:
    $key_8f3d = { d8 4f [2] ea 6d [2] ec 58 [2] c2 58 [2] fd 44 }

  condition:
    any of them
}