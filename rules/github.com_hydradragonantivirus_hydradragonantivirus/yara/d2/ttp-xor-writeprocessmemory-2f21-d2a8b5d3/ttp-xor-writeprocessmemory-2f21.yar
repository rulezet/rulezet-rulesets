rule TTP_XOR_WriteProcessMemory_2f21 {
  strings:
    $key_2f21 = { 78 53 [2] 4a 71 [2] 4c 44 [2] 62 44 [2] 5d 58 }

  condition:
    any of them
}