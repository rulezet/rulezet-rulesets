rule TTP_XOR_WriteProcessMemory_61d3 {
  strings:
    $key_61d3 = { 36 a1 [2] 04 83 [2] 02 b6 [2] 2c b6 [2] 13 aa }

  condition:
    any of them
}