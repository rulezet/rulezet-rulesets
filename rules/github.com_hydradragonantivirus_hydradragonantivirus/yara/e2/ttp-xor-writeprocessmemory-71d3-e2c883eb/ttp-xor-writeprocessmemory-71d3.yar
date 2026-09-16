rule TTP_XOR_WriteProcessMemory_71d3 {
  strings:
    $key_71d3 = { 26 a1 [2] 14 83 [2] 12 b6 [2] 3c b6 [2] 03 aa }

  condition:
    any of them
}