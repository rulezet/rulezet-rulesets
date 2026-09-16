rule TTP_XOR_WriteProcessMemory_2ff5 {
  strings:
    $key_2ff5 = { 78 87 [2] 4a a5 [2] 4c 90 [2] 62 90 [2] 5d 8c }

  condition:
    any of them
}