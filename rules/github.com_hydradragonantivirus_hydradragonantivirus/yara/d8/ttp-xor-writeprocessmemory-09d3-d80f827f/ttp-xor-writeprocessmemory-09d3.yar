rule TTP_XOR_WriteProcessMemory_09d3 {
  strings:
    $key_09d3 = { 5e a1 [2] 6c 83 [2] 6a b6 [2] 44 b6 [2] 7b aa }

  condition:
    any of them
}