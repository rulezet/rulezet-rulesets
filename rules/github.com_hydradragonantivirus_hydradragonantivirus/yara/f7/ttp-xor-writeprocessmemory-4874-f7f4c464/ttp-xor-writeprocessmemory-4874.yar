rule TTP_XOR_WriteProcessMemory_4874 {
  strings:
    $key_4874 = { 1f 06 [2] 2d 24 [2] 2b 11 [2] 05 11 [2] 3a 0d }

  condition:
    any of them
}