rule TTP_XOR_WriteProcessMemory_6b94 {
  strings:
    $key_6b94 = { 3c e6 [2] 0e c4 [2] 08 f1 [2] 26 f1 [2] 19 ed }

  condition:
    any of them
}