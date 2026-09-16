rule TTP_XOR_WriteProcessMemory_6047 {
  strings:
    $key_6047 = { 37 35 [2] 05 17 [2] 03 22 [2] 2d 22 [2] 12 3e }

  condition:
    any of them
}