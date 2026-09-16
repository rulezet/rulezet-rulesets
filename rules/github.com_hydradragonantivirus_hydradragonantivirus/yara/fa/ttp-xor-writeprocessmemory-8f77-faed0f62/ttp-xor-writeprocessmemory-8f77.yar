rule TTP_XOR_WriteProcessMemory_8f77 {
  strings:
    $key_8f77 = { d8 05 [2] ea 27 [2] ec 12 [2] c2 12 [2] fd 0e }

  condition:
    any of them
}