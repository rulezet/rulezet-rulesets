rule TTP_XOR_WriteProcessMemory_3960 {
  strings:
    $key_3960 = { 6e 12 [2] 5c 30 [2] 5a 05 [2] 74 05 [2] 4b 19 }

  condition:
    any of them
}