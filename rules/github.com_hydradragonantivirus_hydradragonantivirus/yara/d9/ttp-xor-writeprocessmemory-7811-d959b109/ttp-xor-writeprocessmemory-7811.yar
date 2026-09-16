rule TTP_XOR_WriteProcessMemory_7811 {
  strings:
    $key_7811 = { 2f 63 [2] 1d 41 [2] 1b 74 [2] 35 74 [2] 0a 68 }

  condition:
    any of them
}