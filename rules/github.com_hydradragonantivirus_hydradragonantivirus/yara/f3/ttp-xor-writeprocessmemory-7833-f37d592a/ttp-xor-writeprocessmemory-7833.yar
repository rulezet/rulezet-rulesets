rule TTP_XOR_WriteProcessMemory_7833 {
  strings:
    $key_7833 = { 2f 41 [2] 1d 63 [2] 1b 56 [2] 35 56 [2] 0a 4a }

  condition:
    any of them
}