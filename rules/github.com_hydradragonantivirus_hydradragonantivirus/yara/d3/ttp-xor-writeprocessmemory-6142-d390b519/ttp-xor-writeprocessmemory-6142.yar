rule TTP_XOR_WriteProcessMemory_6142 {
  strings:
    $key_6142 = { 36 30 [2] 04 12 [2] 02 27 [2] 2c 27 [2] 13 3b }

  condition:
    any of them
}