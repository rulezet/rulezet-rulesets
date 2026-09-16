rule TTP_XOR_WriteProcessMemory_2f94 {
  strings:
    $key_2f94 = { 78 e6 [2] 4a c4 [2] 4c f1 [2] 62 f1 [2] 5d ed }

  condition:
    any of them
}