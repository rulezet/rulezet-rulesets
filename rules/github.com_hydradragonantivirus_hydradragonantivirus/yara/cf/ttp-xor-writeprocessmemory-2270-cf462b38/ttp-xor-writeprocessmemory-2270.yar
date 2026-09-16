rule TTP_XOR_WriteProcessMemory_2270 {
  strings:
    $key_2270 = { 75 02 [2] 47 20 [2] 41 15 [2] 6f 15 [2] 50 09 }

  condition:
    any of them
}