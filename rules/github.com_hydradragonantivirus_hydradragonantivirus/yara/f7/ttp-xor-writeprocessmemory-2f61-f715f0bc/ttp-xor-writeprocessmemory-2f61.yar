rule TTP_XOR_WriteProcessMemory_2f61 {
  strings:
    $key_2f61 = { 78 13 [2] 4a 31 [2] 4c 04 [2] 62 04 [2] 5d 18 }

  condition:
    any of them
}