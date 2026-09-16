rule TTP_XOR_WriteProcessMemory_7214 {
  strings:
    $key_7214 = { 25 66 [2] 17 44 [2] 11 71 [2] 3f 71 [2] 00 6d }

  condition:
    any of them
}