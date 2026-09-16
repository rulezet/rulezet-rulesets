rule TTP_XOR_WriteProcessMemory_4a61 {
  strings:
    $key_4a61 = { 1d 13 [2] 2f 31 [2] 29 04 [2] 07 04 [2] 38 18 }

  condition:
    any of them
}