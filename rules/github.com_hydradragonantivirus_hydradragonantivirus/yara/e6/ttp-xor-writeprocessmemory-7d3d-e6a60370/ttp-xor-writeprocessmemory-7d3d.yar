rule TTP_XOR_WriteProcessMemory_7d3d {
  strings:
    $key_7d3d = { 2a 4f [2] 18 6d [2] 1e 58 [2] 30 58 [2] 0f 44 }

  condition:
    any of them
}