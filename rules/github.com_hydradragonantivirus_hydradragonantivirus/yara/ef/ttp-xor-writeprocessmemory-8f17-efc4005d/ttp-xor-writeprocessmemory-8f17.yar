rule TTP_XOR_WriteProcessMemory_8f17 {
  strings:
    $key_8f17 = { d8 65 [2] ea 47 [2] ec 72 [2] c2 72 [2] fd 6e }

  condition:
    any of them
}