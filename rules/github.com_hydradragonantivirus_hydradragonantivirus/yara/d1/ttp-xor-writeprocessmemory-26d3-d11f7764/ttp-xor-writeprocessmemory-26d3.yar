rule TTP_XOR_WriteProcessMemory_26d3 {
  strings:
    $key_26d3 = { 71 a1 [2] 43 83 [2] 45 b6 [2] 6b b6 [2] 54 aa }

  condition:
    any of them
}