rule TTP_XOR_WriteProcessMemory_8f8b {
  strings:
    $key_8f8b = { d8 f9 [2] ea db [2] ec ee [2] c2 ee [2] fd f2 }

  condition:
    any of them
}