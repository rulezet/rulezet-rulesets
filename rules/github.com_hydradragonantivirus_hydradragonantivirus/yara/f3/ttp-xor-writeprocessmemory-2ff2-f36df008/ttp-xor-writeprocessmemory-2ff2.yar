rule TTP_XOR_WriteProcessMemory_2ff2 {
  strings:
    $key_2ff2 = { 78 80 [2] 4a a2 [2] 4c 97 [2] 62 97 [2] 5d 8b }

  condition:
    any of them
}