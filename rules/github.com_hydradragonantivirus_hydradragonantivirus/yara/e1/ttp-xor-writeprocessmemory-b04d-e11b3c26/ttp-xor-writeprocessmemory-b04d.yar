rule TTP_XOR_WriteProcessMemory_b04d {
  strings:
    $key_b04d = { e7 3f [2] d5 1d [2] d3 28 [2] fd 28 [2] c2 34 }

  condition:
    any of them
}