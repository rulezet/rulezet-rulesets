rule TTP_XOR_WriteProcessMemory_22d3 {
  strings:
    $key_22d3 = { 75 a1 [2] 47 83 [2] 41 b6 [2] 6f b6 [2] 50 aa }

  condition:
    any of them
}