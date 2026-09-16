rule TTP_XOR_WriteProcessMemory_b02d {
  strings:
    $key_b02d = { e7 5f [2] d5 7d [2] d3 48 [2] fd 48 [2] c2 54 }

  condition:
    any of them
}