rule TTP_XOR_WriteProcessMemory_4ee1 {
  strings:
    $key_4ee1 = { 19 93 [2] 2b b1 [2] 2d 84 [2] 03 84 [2] 3c 98 }

  condition:
    any of them
}