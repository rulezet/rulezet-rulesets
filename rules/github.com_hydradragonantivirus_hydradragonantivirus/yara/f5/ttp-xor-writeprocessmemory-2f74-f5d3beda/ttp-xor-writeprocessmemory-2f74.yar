rule TTP_XOR_WriteProcessMemory_2f74 {
  strings:
    $key_2f74 = { 78 06 [2] 4a 24 [2] 4c 11 [2] 62 11 [2] 5d 0d }

  condition:
    any of them
}