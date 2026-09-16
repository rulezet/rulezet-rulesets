rule TTP_XOR_WriteProcessMemory_4e37 {
  strings:
    $key_4e37 = { 19 45 [2] 2b 67 [2] 2d 52 [2] 03 52 [2] 3c 4e }

  condition:
    any of them
}