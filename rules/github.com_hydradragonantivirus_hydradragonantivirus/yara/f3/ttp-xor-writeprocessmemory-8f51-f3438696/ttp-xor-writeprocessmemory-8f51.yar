rule TTP_XOR_WriteProcessMemory_8f51 {
  strings:
    $key_8f51 = { d8 23 [2] ea 01 [2] ec 34 [2] c2 34 [2] fd 28 }

  condition:
    any of them
}