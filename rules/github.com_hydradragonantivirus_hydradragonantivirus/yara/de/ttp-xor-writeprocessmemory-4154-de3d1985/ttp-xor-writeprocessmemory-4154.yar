rule TTP_XOR_WriteProcessMemory_4154 {
  strings:
    $key_4154 = { 16 26 [2] 24 04 [2] 22 31 [2] 0c 31 [2] 33 2d }

  condition:
    any of them
}