rule TTP_XOR_WriteProcessMemory_4ee2 {
  strings:
    $key_4ee2 = { 19 90 [2] 2b b2 [2] 2d 87 [2] 03 87 [2] 3c 9b }

  condition:
    any of them
}