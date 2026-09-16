rule TTP_XOR_WriteProcessMemory_4194 {
  strings:
    $key_4194 = { 16 e6 [2] 24 c4 [2] 22 f1 [2] 0c f1 [2] 33 ed }

  condition:
    any of them
}