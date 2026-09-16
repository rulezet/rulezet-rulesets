rule TTP_XOR_WriteProcessMemory_21d3 {
  strings:
    $key_21d3 = { 76 a1 [2] 44 83 [2] 42 b6 [2] 6c b6 [2] 53 aa }

  condition:
    any of them
}