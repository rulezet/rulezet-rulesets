rule TTP_XOR_WriteProcessMemory_36f1 {
  strings:
    $key_36f1 = { 61 83 [2] 53 a1 [2] 55 94 [2] 7b 94 [2] 44 88 }

  condition:
    any of them
}