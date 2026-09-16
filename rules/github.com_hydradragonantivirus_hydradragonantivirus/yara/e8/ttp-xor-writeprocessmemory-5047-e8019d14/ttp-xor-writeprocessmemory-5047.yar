rule TTP_XOR_WriteProcessMemory_5047 {
  strings:
    $key_5047 = { 07 35 [2] 35 17 [2] 33 22 [2] 1d 22 [2] 22 3e }

  condition:
    any of them
}