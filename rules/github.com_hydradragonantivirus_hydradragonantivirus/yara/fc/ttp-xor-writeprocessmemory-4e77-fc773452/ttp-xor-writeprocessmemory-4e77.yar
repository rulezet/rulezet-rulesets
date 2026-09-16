rule TTP_XOR_WriteProcessMemory_4e77 {
  strings:
    $key_4e77 = { 19 05 [2] 2b 27 [2] 2d 12 [2] 03 12 [2] 3c 0e }

  condition:
    any of them
}