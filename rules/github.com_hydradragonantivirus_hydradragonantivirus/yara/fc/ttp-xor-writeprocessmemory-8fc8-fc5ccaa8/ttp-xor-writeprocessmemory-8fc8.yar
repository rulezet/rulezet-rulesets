rule TTP_XOR_WriteProcessMemory_8fc8 {
  strings:
    $key_8fc8 = { d8 ba [2] ea 98 [2] ec ad [2] c2 ad [2] fd b1 }

  condition:
    any of them
}