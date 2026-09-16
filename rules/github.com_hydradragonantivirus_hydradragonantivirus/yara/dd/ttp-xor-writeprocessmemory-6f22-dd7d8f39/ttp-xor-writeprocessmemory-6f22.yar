rule TTP_XOR_WriteProcessMemory_6f22 {
  strings:
    $key_6f22 = { 38 50 [2] 0a 72 [2] 0c 47 [2] 22 47 [2] 1d 5b }

  condition:
    any of them
}