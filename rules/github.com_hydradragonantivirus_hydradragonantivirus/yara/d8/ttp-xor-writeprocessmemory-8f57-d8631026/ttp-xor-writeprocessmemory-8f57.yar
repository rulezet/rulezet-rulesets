rule TTP_XOR_WriteProcessMemory_8f57 {
  strings:
    $key_8f57 = { d8 25 [2] ea 07 [2] ec 32 [2] c2 32 [2] fd 2e }

  condition:
    any of them
}