rule TTP_XOR_WriteProcessMemory_b786 {
  strings:
    $key_b786 = { e0 f4 [2] d2 d6 [2] d4 e3 [2] fa e3 [2] c5 ff }

  condition:
    any of them
}