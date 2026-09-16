rule TTP_XOR_WriteProcessMemory_4e14 {
  strings:
    $key_4e14 = { 19 66 [2] 2b 44 [2] 2d 71 [2] 03 71 [2] 3c 6d }

  condition:
    any of them
}