rule TTP_XOR_WriteProcessMemory_7f70 {
  strings:
    $key_7f70 = { 28 02 [2] 1a 20 [2] 1c 15 [2] 32 15 [2] 0d 09 }

  condition:
    any of them
}