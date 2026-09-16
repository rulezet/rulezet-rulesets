rule TTP_XOR_WriteProcessMemory_6f74 {
  strings:
    $key_6f74 = { 38 06 [2] 0a 24 [2] 0c 11 [2] 22 11 [2] 1d 0d }

  condition:
    any of them
}