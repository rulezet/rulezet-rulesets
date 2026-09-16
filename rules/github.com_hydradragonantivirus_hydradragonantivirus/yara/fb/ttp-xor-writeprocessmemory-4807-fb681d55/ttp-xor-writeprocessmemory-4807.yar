rule TTP_XOR_WriteProcessMemory_4807 {
  strings:
    $key_4807 = { 1f 75 [2] 2d 57 [2] 2b 62 [2] 05 62 [2] 3a 7e }

  condition:
    any of them
}