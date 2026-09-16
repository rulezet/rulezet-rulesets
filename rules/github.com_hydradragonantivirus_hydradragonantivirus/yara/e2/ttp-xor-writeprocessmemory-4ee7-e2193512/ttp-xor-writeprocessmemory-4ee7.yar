rule TTP_XOR_WriteProcessMemory_4ee7 {
  strings:
    $key_4ee7 = { 19 95 [2] 2b b7 [2] 2d 82 [2] 03 82 [2] 3c 9e }

  condition:
    any of them
}