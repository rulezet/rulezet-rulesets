rule TTP_XOR_WriteProcessMemory_8fc1 {
  strings:
    $key_8fc1 = { d8 b3 [2] ea 91 [2] ec a4 [2] c2 a4 [2] fd b8 }

  condition:
    any of them
}