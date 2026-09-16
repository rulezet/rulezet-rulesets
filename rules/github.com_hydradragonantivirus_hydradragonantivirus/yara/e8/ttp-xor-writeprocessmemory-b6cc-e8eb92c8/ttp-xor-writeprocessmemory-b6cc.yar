rule TTP_XOR_WriteProcessMemory_b6cc {
  strings:
    $key_b6cc = { e1 be [2] d3 9c [2] d5 a9 [2] fb a9 [2] c4 b5 }

  condition:
    any of them
}