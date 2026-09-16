rule TTP_XOR_WriteProcessMemory_1444 {
  strings:
    $key_1444 = { 43 36 [2] 71 14 [2] 77 21 [2] 59 21 [2] 66 3d }

  condition:
    any of them
}