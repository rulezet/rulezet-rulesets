rule TTP_XOR_WriteProcessMemory_3f70 {
  strings:
    $key_3f70 = { 68 02 [2] 5a 20 [2] 5c 15 [2] 72 15 [2] 4d 09 }

  condition:
    any of them
}