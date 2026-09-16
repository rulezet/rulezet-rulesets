rule TTP_XOR_WriteProcessMemory_e9d3 {
  strings:
    $key_e9d3 = { be a1 [2] 8c 83 [2] 8a b6 [2] a4 b6 [2] 9b aa }

  condition:
    any of them
}