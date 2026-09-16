rule TTP_XOR_WriteProcessMemory_8fe0 {
  strings:
    $key_8fe0 = { d8 92 [2] ea b0 [2] ec 85 [2] c2 85 [2] fd 99 }

  condition:
    any of them
}