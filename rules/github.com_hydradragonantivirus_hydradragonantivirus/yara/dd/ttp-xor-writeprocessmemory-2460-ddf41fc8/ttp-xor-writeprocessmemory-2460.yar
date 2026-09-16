rule TTP_XOR_WriteProcessMemory_2460 {
  strings:
    $key_2460 = { 73 12 [2] 41 30 [2] 47 05 [2] 69 05 [2] 56 19 }

  condition:
    any of them
}