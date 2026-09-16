rule TTP_XOR_WriteProcessMemory_3f94 {
  strings:
    $key_3f94 = { 68 e6 [2] 5a c4 [2] 5c f1 [2] 72 f1 [2] 4d ed }

  condition:
    any of them
}