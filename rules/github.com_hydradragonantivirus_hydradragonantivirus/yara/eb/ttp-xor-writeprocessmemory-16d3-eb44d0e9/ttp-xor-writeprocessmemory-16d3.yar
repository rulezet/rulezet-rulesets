rule TTP_XOR_WriteProcessMemory_16d3 {
  strings:
    $key_16d3 = { 41 a1 [2] 73 83 [2] 75 b6 [2] 5b b6 [2] 64 aa }

  condition:
    any of them
}