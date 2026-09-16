rule TTP_XOR_WriteProcessMemory_7a07 {
  strings:
    $key_7a07 = { 2d 75 [2] 1f 57 [2] 19 62 [2] 37 62 [2] 08 7e }

  condition:
    any of them
}