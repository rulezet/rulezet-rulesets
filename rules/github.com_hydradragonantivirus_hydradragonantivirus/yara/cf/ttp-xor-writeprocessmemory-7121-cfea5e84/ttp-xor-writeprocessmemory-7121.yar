rule TTP_XOR_WriteProcessMemory_7121 {
  strings:
    $key_7121 = { 26 53 [2] 14 71 [2] 12 44 [2] 3c 44 [2] 03 58 }

  condition:
    any of them
}