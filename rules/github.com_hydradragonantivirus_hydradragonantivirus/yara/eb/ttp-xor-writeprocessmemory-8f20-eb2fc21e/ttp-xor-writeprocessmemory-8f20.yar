rule TTP_XOR_WriteProcessMemory_8f20 {
  strings:
    $key_8f20 = { d8 52 [2] ea 70 [2] ec 45 [2] c2 45 [2] fd 59 }

  condition:
    any of them
}