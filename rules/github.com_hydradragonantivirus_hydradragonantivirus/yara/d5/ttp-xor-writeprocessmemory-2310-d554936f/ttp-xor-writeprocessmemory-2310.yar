rule TTP_XOR_WriteProcessMemory_2310 {
  strings:
    $key_2310 = { 74 62 [2] 46 40 [2] 40 75 [2] 6e 75 [2] 51 69 }

  condition:
    any of them
}