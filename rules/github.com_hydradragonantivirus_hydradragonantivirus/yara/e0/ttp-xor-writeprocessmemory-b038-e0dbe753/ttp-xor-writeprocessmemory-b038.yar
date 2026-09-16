rule TTP_XOR_WriteProcessMemory_b038 {
  strings:
    $key_b038 = { e7 4a [2] d5 68 [2] d3 5d [2] fd 5d [2] c2 41 }

  condition:
    any of them
}