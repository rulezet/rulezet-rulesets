rule TTP_XOR_WriteProcessMemory_3c60 {
  strings:
    $key_3c60 = { 6b 12 [2] 59 30 [2] 5f 05 [2] 71 05 [2] 4e 19 }

  condition:
    any of them
}