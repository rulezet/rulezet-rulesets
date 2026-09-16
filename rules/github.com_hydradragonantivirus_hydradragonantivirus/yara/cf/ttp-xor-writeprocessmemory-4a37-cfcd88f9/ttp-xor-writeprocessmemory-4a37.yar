rule TTP_XOR_WriteProcessMemory_4a37 {
  strings:
    $key_4a37 = { 1d 45 [2] 2f 67 [2] 29 52 [2] 07 52 [2] 38 4e }

  condition:
    any of them
}