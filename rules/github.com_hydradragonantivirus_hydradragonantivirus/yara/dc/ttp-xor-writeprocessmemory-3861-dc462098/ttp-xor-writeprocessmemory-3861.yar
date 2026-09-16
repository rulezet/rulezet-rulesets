rule TTP_XOR_WriteProcessMemory_3861 {
  strings:
    $key_3861 = { 6f 13 [2] 5d 31 [2] 5b 04 [2] 75 04 [2] 4a 18 }

  condition:
    any of them
}