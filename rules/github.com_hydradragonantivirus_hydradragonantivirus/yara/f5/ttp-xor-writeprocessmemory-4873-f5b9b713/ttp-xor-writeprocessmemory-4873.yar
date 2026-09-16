rule TTP_XOR_WriteProcessMemory_4873 {
  strings:
    $key_4873 = { 1f 01 [2] 2d 23 [2] 2b 16 [2] 05 16 [2] 3a 0a }

  condition:
    any of them
}