rule TTP_XOR_WriteProcessMemory_43f1 {
  strings:
    $key_43f1 = { 14 83 [2] 26 a1 [2] 20 94 [2] 0e 94 [2] 31 88 }

  condition:
    any of them
}