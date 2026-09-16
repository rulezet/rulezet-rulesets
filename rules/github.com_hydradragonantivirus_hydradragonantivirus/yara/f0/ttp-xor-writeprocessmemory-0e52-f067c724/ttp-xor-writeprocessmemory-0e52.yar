rule TTP_XOR_WriteProcessMemory_0e52 {
  strings:
    $key_0e52 = { 59 20 [2] 6b 02 [2] 6d 37 [2] 43 37 [2] 7c 2b }

  condition:
    any of them
}