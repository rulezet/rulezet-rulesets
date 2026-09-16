rule TTP_XOR_WriteProcessMemory_8f50 {
  strings:
    $key_8f50 = { d8 22 [2] ea 00 [2] ec 35 [2] c2 35 [2] fd 29 }

  condition:
    any of them
}