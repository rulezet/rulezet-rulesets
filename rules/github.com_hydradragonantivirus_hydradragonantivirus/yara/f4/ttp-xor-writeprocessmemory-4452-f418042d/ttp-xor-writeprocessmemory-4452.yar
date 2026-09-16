rule TTP_XOR_WriteProcessMemory_4452 {
  strings:
    $key_4452 = { 13 20 [2] 21 02 [2] 27 37 [2] 09 37 [2] 36 2b }

  condition:
    any of them
}