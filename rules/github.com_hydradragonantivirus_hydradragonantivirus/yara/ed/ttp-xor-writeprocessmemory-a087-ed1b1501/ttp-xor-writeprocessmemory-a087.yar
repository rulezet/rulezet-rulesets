rule TTP_XOR_WriteProcessMemory_a087 {
  strings:
    $key_a087 = { f7 f5 [2] c5 d7 [2] c3 e2 [2] ed e2 [2] d2 fe }

  condition:
    any of them
}