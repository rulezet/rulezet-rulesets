rule TTP_XOR_WriteProcessMemory_6f54 {
  strings:
    $key_6f54 = { 38 26 [2] 0a 04 [2] 0c 31 [2] 22 31 [2] 1d 2d }

  condition:
    any of them
}