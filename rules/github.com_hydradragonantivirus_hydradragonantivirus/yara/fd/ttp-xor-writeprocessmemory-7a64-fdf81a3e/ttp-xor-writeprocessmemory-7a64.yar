rule TTP_XOR_WriteProcessMemory_7a64 {
  strings:
    $key_7a64 = { 2d 16 [2] 1f 34 [2] 19 01 [2] 37 01 [2] 08 1d }

  condition:
    any of them
}