rule TTP_XOR_WriteProcessMemory_3f52 {
  strings:
    $key_3f52 = { 68 20 [2] 5a 02 [2] 5c 37 [2] 72 37 [2] 4d 2b }

  condition:
    any of them
}