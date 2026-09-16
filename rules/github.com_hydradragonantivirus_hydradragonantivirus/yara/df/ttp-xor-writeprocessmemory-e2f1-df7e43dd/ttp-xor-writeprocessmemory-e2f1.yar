rule TTP_XOR_WriteProcessMemory_e2f1 {
  strings:
    $key_e2f1 = { b5 83 [2] 87 a1 [2] 81 94 [2] af 94 [2] 90 88 }

  condition:
    any of them
}