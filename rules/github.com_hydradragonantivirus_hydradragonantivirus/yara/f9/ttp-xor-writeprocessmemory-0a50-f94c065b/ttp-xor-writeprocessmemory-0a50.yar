rule TTP_XOR_WriteProcessMemory_0a50 {
  strings:
    $key_0a50 = { 5d 22 [2] 6f 00 [2] 69 35 [2] 47 35 [2] 78 29 }

  condition:
    any of them
}