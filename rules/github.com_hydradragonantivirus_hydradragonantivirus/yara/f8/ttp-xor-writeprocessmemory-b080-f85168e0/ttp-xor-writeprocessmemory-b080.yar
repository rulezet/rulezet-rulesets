rule TTP_XOR_WriteProcessMemory_b080 {
  strings:
    $key_b080 = { e7 f2 [2] d5 d0 [2] d3 e5 [2] fd e5 [2] c2 f9 }

  condition:
    any of them
}