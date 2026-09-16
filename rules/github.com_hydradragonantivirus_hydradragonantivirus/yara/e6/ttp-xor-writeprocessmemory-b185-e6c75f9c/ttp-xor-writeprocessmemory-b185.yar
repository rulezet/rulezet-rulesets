rule TTP_XOR_WriteProcessMemory_b185 {
  strings:
    $key_b185 = { e6 f7 [2] d4 d5 [2] d2 e0 [2] fc e0 [2] c3 fc }

  condition:
    any of them
}