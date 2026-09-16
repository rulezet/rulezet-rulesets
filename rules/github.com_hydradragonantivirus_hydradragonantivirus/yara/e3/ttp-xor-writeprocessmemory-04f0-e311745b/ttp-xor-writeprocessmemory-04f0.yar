rule TTP_XOR_WriteProcessMemory_04f0 {
  strings:
    $key_04f0 = { 53 82 [2] 61 a0 [2] 67 95 [2] 49 95 [2] 76 89 }

  condition:
    any of them
}