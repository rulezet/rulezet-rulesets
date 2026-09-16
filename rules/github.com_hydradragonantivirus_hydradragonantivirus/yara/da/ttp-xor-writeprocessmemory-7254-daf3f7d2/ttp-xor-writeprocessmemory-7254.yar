rule TTP_XOR_WriteProcessMemory_7254 {
  strings:
    $key_7254 = { 25 26 [2] 17 04 [2] 11 31 [2] 3f 31 [2] 00 2d }

  condition:
    any of them
}