rule TTP_XOR_WriteProcessMemory_6d3d {
  strings:
    $key_6d3d = { 3a 4f [2] 08 6d [2] 0e 58 [2] 20 58 [2] 1f 44 }

  condition:
    any of them
}