rule TTP_XOR_WriteProcessMemory_6254 {
  strings:
    $key_6254 = { 35 26 [2] 07 04 [2] 01 31 [2] 2f 31 [2] 10 2d }

  condition:
    any of them
}