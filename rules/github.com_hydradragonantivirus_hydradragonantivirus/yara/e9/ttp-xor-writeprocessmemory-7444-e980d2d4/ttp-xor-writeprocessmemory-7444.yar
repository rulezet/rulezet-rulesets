rule TTP_XOR_WriteProcessMemory_7444 {
  strings:
    $key_7444 = { 23 36 [2] 11 14 [2] 17 21 [2] 39 21 [2] 06 3d }

  condition:
    any of them
}