rule TTP_XOR_WriteProcessMemory_3f43 {
  strings:
    $key_3f43 = { 68 31 [2] 5a 13 [2] 5c 26 [2] 72 26 [2] 4d 3a }

  condition:
    any of them
}