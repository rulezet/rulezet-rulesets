rule TTP_XOR_WriteProcessMemory_8f54 {
  strings:
    $key_8f54 = { d8 26 [2] ea 04 [2] ec 31 [2] c2 31 [2] fd 2d }

  condition:
    any of them
}