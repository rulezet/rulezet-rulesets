rule TTP_XOR_WriteProcessMemory_4e24 {
  strings:
    $key_4e24 = { 19 56 [2] 2b 74 [2] 2d 41 [2] 03 41 [2] 3c 5d }

  condition:
    any of them
}