rule TTP_XOR_WriteProcessMemory_8f89 {
  strings:
    $key_8f89 = { d8 fb [2] ea d9 [2] ec ec [2] c2 ec [2] fd f0 }

  condition:
    any of them
}