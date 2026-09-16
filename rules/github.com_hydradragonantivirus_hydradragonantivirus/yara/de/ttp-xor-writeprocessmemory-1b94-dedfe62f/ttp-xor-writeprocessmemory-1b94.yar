rule TTP_XOR_WriteProcessMemory_1b94 {
  strings:
    $key_1b94 = { 4c e6 [2] 7e c4 [2] 78 f1 [2] 56 f1 [2] 69 ed }

  condition:
    any of them
}