rule TTP_XOR_WriteProcessMemory_8f21 {
  strings:
    $key_8f21 = { d8 53 [2] ea 71 [2] ec 44 [2] c2 44 [2] fd 58 }

  condition:
    any of them
}