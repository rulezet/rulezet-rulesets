rule TTP_XOR_WriteProcessMemory_54d3 {
  strings:
    $key_54d3 = { 03 a1 [2] 31 83 [2] 37 b6 [2] 19 b6 [2] 26 aa }

  condition:
    any of them
}