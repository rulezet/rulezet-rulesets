rule TTP_XOR_WriteProcessMemory_8f04 {
  strings:
    $key_8f04 = { d8 76 [2] ea 54 [2] ec 61 [2] c2 61 [2] fd 7d }

  condition:
    any of them
}