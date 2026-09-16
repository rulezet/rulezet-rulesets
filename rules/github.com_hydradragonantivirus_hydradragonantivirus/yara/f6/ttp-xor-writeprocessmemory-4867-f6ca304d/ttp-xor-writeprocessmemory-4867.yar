rule TTP_XOR_WriteProcessMemory_4867 {
  strings:
    $key_4867 = { 1f 15 [2] 2d 37 [2] 2b 02 [2] 05 02 [2] 3a 1e }

  condition:
    any of them
}