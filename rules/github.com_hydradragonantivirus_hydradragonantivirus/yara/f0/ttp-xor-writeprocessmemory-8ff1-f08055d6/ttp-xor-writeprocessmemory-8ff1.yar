rule TTP_XOR_WriteProcessMemory_8ff1 {
  strings:
    $key_8ff1 = { d8 83 [2] ea a1 [2] ec 94 [2] c2 94 [2] fd 88 }

  condition:
    any of them
}