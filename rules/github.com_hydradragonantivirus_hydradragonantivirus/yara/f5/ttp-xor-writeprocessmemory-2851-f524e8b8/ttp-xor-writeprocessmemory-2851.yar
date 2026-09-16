rule TTP_XOR_WriteProcessMemory_2851 {
  strings:
    $key_2851 = { 7f 23 [2] 4d 01 [2] 4b 34 [2] 65 34 [2] 5a 28 }

  condition:
    any of them
}