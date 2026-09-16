rule TTP_XOR_WriteProcessMemory_39d3 {
  strings:
    $key_39d3 = { 6e a1 [2] 5c 83 [2] 5a b6 [2] 74 b6 [2] 4b aa }

  condition:
    any of them
}