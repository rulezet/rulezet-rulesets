rule TTP_XOR_WriteProcessMemory_2110 {
  strings:
    $key_2110 = { 76 62 [2] 44 40 [2] 42 75 [2] 6c 75 [2] 53 69 }

  condition:
    any of them
}