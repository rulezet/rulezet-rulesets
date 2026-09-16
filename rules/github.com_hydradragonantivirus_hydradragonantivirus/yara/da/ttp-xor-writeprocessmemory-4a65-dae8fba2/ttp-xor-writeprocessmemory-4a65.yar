rule TTP_XOR_WriteProcessMemory_4a65 {
  strings:
    $key_4a65 = { 1d 17 [2] 2f 35 [2] 29 00 [2] 07 00 [2] 38 1c }

  condition:
    any of them
}