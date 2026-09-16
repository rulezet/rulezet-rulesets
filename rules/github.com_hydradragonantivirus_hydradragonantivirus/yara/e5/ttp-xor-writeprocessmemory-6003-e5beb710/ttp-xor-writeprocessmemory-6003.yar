rule TTP_XOR_WriteProcessMemory_6003 {
  strings:
    $key_6003 = { 37 71 [2] 05 53 [2] 03 66 [2] 2d 66 [2] 12 7a }

  condition:
    any of them
}