rule TTP_XOR_WriteProcessMemory_8f94 {
  strings:
    $key_8f94 = { d8 e6 [2] ea c4 [2] ec f1 [2] c2 f1 [2] fd ed }

  condition:
    any of them
}