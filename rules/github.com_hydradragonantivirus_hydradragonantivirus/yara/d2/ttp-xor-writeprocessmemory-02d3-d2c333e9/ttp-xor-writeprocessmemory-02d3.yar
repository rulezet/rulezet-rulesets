rule TTP_XOR_WriteProcessMemory_02d3 {
  strings:
    $key_02d3 = { 55 a1 [2] 67 83 [2] 61 b6 [2] 4f b6 [2] 70 aa }

  condition:
    any of them
}