rule TTP_XOR_WriteProcessMemory_b0f9 {
  strings:
    $key_b0f9 = { e7 8b [2] d5 a9 [2] d3 9c [2] fd 9c [2] c2 80 }

  condition:
    any of them
}