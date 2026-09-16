rule TTP_XOR_WriteProcessMemory_31f1 {
  strings:
    $key_31f1 = { 66 83 [2] 54 a1 [2] 52 94 [2] 7c 94 [2] 43 88 }

  condition:
    any of them
}