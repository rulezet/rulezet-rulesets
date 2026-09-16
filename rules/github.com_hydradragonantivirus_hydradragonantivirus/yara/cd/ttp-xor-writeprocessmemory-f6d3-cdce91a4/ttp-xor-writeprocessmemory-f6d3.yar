rule TTP_XOR_WriteProcessMemory_f6d3 {
  strings:
    $key_f6d3 = { a1 a1 [2] 93 83 [2] 95 b6 [2] bb b6 [2] 84 aa }

  condition:
    any of them
}