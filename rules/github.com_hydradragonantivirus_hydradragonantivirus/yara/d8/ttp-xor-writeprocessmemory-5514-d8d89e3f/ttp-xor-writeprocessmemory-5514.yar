rule TTP_XOR_WriteProcessMemory_5514 {
  strings:
    $key_5514 = { 02 66 [2] 30 44 [2] 36 71 [2] 18 71 [2] 27 6d }

  condition:
    any of them
}