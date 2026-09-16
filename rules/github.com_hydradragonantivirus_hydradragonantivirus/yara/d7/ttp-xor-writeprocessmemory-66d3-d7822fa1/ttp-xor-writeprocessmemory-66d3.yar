rule TTP_XOR_WriteProcessMemory_66d3 {
  strings:
    $key_66d3 = { 31 a1 [2] 03 83 [2] 05 b6 [2] 2b b6 [2] 14 aa }

  condition:
    any of them
}