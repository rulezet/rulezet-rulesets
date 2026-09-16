rule TTP_XOR_WriteProcessMemory_0a73 {
  strings:
    $key_0a73 = { 5d 01 [2] 6f 23 [2] 69 16 [2] 47 16 [2] 78 0a }

  condition:
    any of them
}