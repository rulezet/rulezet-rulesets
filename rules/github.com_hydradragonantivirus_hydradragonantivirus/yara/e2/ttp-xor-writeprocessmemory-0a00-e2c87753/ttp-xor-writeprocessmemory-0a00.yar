rule TTP_XOR_WriteProcessMemory_0a00 {
  strings:
    $key_0a00 = { 5d 72 [2] 6f 50 [2] 69 65 [2] 47 65 [2] 78 79 }

  condition:
    any of them
}