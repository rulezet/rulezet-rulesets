rule TTP_XOR_WriteProcessMemory_2ff0 {
  strings:
    $key_2ff0 = { 78 82 [2] 4a a0 [2] 4c 95 [2] 62 95 [2] 5d 89 }

  condition:
    any of them
}