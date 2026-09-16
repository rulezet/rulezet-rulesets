rule TTP_XOR_WriteProcessMemory_5f24 {
  strings:
    $key_5f24 = { 08 56 [2] 3a 74 [2] 3c 41 [2] 12 41 [2] 2d 5d }

  condition:
    any of them
}