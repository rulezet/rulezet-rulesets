rule TTP_XOR_WriteProcessMemory_8f06 {
  strings:
    $key_8f06 = { d8 74 [2] ea 56 [2] ec 63 [2] c2 63 [2] fd 7f }

  condition:
    any of them
}