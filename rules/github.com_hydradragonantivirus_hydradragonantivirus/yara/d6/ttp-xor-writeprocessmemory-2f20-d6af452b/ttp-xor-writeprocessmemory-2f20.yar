rule TTP_XOR_WriteProcessMemory_2f20 {
  strings:
    $key_2f20 = { 78 52 [2] 4a 70 [2] 4c 45 [2] 62 45 [2] 5d 59 }

  condition:
    any of them
}