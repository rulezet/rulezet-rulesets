rule TTP_XOR_WriteProcessMemory_8fe6 {
  strings:
    $key_8fe6 = { d8 94 [2] ea b6 [2] ec 83 [2] c2 83 [2] fd 9f }

  condition:
    any of them
}