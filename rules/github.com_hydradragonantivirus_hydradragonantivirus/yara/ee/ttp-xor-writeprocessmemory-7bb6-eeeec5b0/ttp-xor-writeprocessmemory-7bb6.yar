rule TTP_XOR_WriteProcessMemory_7bb6 {
  strings:
    $key_7bb6 = { 2c c4 [2] 1e e6 [2] 18 d3 [2] 36 d3 [2] 09 cf }

  condition:
    any of them
}