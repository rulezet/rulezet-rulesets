rule TTP_XOR_WriteProcessMemory_8982 {
  strings:
    $key_8982 = { de f0 [2] ec d2 [2] ea e7 [2] c4 e7 [2] fb fb }

  condition:
    any of them
}