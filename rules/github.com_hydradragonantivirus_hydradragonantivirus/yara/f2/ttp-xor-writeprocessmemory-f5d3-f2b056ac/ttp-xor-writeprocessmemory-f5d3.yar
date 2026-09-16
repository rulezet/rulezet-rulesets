rule TTP_XOR_WriteProcessMemory_f5d3 {
  strings:
    $key_f5d3 = { a2 a1 [2] 90 83 [2] 96 b6 [2] b8 b6 [2] 87 aa }

  condition:
    any of them
}