rule TTP_XOR_WriteProcessMemory_10d3 {
  strings:
    $key_10d3 = { 47 a1 [2] 75 83 [2] 73 b6 [2] 5d b6 [2] 62 aa }

  condition:
    any of them
}