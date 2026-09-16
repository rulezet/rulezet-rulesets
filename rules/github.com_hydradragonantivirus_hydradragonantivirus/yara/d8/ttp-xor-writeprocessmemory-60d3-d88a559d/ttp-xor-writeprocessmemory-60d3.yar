rule TTP_XOR_WriteProcessMemory_60d3 {
  strings:
    $key_60d3 = { 37 a1 [2] 05 83 [2] 03 b6 [2] 2d b6 [2] 12 aa }

  condition:
    any of them
}