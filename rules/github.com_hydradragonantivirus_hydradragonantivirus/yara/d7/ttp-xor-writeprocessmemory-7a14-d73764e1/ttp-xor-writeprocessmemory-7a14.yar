rule TTP_XOR_WriteProcessMemory_7a14 {
  strings:
    $key_7a14 = { 2d 66 [2] 1f 44 [2] 19 71 [2] 37 71 [2] 08 6d }

  condition:
    any of them
}