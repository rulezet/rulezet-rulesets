rule TTP_XOR_WriteProcessMemory_2f24 {
  strings:
    $key_2f24 = { 78 56 [2] 4a 74 [2] 4c 41 [2] 62 41 [2] 5d 5d }

  condition:
    any of them
}