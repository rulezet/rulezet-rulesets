rule TTP_XOR_WriteProcessMemory_4a31 {
  strings:
    $key_4a31 = { 1d 43 [2] 2f 61 [2] 29 54 [2] 07 54 [2] 38 48 }

  condition:
    any of them
}