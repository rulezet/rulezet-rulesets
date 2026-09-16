rule TTP_XOR_WriteProcessMemory_8f03 {
  strings:
    $key_8f03 = { d8 71 [2] ea 53 [2] ec 66 [2] c2 66 [2] fd 7a }

  condition:
    any of them
}