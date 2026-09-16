rule TTP_XOR_WriteProcessMemory_2f30 {
  strings:
    $key_2f30 = { 78 42 [2] 4a 60 [2] 4c 55 [2] 62 55 [2] 5d 49 }

  condition:
    any of them
}