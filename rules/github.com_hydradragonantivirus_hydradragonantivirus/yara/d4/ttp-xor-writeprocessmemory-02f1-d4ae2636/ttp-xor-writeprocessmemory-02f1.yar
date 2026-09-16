rule TTP_XOR_WriteProcessMemory_02f1 {
  strings:
    $key_02f1 = { 55 83 [2] 67 a1 [2] 61 94 [2] 4f 94 [2] 70 88 }

  condition:
    any of them
}