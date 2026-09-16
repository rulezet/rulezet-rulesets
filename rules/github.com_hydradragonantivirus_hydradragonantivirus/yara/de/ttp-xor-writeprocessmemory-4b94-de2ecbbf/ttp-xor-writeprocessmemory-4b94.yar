rule TTP_XOR_WriteProcessMemory_4b94 {
  strings:
    $key_4b94 = { 1c e6 [2] 2e c4 [2] 28 f1 [2] 06 f1 [2] 39 ed }

  condition:
    any of them
}