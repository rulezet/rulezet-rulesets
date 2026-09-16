rule TTP_XOR_WriteProcessMemory_2864 {
  strings:
    $key_2864 = { 7f 16 [2] 4d 34 [2] 4b 01 [2] 65 01 [2] 5a 1d }

  condition:
    any of them
}