rule TTP_XOR_WriteProcessMemory_2a94 {
  strings:
    $key_2a94 = { 7d e6 [2] 4f c4 [2] 49 f1 [2] 67 f1 [2] 58 ed }

  condition:
    any of them
}