rule TTP_XOR_WriteProcessMemory_0cd0 {
  strings:
    $key_0cd0 = { 5b a2 [2] 69 80 [2] 6f b5 [2] 41 b5 [2] 7e a9 }

  condition:
    any of them
}