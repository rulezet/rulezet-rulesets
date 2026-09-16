rule TTP_XOR_WriteProcessMemory_6414 {
  strings:
    $key_6414 = { 33 66 [2] 01 44 [2] 07 71 [2] 29 71 [2] 16 6d }

  condition:
    any of them
}