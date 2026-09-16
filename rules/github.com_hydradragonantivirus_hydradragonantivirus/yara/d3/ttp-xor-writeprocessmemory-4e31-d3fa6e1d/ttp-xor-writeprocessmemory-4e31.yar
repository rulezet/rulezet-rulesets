rule TTP_XOR_WriteProcessMemory_4e31 {
  strings:
    $key_4e31 = { 19 43 [2] 2b 61 [2] 2d 54 [2] 03 54 [2] 3c 48 }

  condition:
    any of them
}