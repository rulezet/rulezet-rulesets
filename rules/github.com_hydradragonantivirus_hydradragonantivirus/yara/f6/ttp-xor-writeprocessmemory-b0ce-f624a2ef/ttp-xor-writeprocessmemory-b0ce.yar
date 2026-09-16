rule TTP_XOR_WriteProcessMemory_b0ce {
  strings:
    $key_b0ce = { e7 bc [2] d5 9e [2] d3 ab [2] fd ab [2] c2 b7 }

  condition:
    any of them
}