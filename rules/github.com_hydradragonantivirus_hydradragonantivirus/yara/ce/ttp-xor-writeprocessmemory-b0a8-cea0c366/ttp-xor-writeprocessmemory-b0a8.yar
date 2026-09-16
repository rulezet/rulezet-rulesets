rule TTP_XOR_WriteProcessMemory_b0a8 {
  strings:
    $key_b0a8 = { e7 da [2] d5 f8 [2] d3 cd [2] fd cd [2] c2 d1 }

  condition:
    any of them
}