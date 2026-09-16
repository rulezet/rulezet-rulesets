rule TTP_XOR_WriteProcessMemory_44d3 {
  strings:
    $key_44d3 = { 13 a1 [2] 21 83 [2] 27 b6 [2] 09 b6 [2] 36 aa }

  condition:
    any of them
}