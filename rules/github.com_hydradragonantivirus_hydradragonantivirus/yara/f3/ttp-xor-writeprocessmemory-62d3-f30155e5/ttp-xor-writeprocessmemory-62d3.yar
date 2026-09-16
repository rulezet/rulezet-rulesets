rule TTP_XOR_WriteProcessMemory_62d3 {
  strings:
    $key_62d3 = { 35 a1 [2] 07 83 [2] 01 b6 [2] 2f b6 [2] 10 aa }

  condition:
    any of them
}