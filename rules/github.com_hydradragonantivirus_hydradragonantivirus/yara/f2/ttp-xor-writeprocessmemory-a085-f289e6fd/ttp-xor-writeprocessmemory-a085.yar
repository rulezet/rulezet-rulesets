rule TTP_XOR_WriteProcessMemory_a085 {
  strings:
    $key_a085 = { f7 f7 [2] c5 d5 [2] c3 e0 [2] ed e0 [2] d2 fc }

  condition:
    any of them
}