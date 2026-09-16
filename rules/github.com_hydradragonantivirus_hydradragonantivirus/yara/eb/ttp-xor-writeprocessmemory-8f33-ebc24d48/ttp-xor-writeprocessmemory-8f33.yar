rule TTP_XOR_WriteProcessMemory_8f33 {
  strings:
    $key_8f33 = { d8 41 [2] ea 63 [2] ec 56 [2] c2 56 [2] fd 4a }

  condition:
    any of them
}