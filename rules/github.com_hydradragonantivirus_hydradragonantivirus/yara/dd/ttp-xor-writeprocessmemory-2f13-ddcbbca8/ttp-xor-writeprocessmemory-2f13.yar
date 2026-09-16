rule TTP_XOR_WriteProcessMemory_2f13 {
  strings:
    $key_2f13 = { 78 61 [2] 4a 43 [2] 4c 76 [2] 62 76 [2] 5d 6a }

  condition:
    any of them
}