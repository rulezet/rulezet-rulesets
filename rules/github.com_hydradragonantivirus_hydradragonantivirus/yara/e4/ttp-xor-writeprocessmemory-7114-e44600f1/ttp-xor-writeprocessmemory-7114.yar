rule TTP_XOR_WriteProcessMemory_7114 {
  strings:
    $key_7114 = { 26 66 [2] 14 44 [2] 12 71 [2] 3c 71 [2] 03 6d }

  condition:
    any of them
}