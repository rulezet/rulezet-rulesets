rule TTP_XOR_WriteProcessMemory_e811 {
  strings:
    $key_e811 = { bf 63 [2] 8d 41 [2] 8b 74 [2] a5 74 [2] 9a 68 }

  condition:
    any of them
}