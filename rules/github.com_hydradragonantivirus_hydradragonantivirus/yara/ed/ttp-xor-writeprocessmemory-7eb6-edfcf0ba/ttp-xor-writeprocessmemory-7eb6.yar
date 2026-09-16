rule TTP_XOR_WriteProcessMemory_7eb6 {
  strings:
    $key_7eb6 = { 29 c4 [2] 1b e6 [2] 1d d3 [2] 33 d3 [2] 0c cf }

  condition:
    any of them
}