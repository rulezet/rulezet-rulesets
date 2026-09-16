rule TTP_XOR_WriteProcessMemory_7a04 {
  strings:
    $key_7a04 = { 2d 76 [2] 1f 54 [2] 19 61 [2] 37 61 [2] 08 7d }

  condition:
    any of them
}