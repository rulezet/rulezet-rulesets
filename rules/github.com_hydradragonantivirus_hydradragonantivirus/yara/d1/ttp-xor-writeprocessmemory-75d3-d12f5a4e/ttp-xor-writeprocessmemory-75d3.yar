rule TTP_XOR_WriteProcessMemory_75d3 {
  strings:
    $key_75d3 = { 22 a1 [2] 10 83 [2] 16 b6 [2] 38 b6 [2] 07 aa }

  condition:
    any of them
}