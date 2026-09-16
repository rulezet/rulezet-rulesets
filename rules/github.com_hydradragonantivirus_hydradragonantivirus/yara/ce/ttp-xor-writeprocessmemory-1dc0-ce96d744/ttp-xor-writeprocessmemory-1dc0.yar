rule TTP_XOR_WriteProcessMemory_1dc0 {
  strings:
    $key_1dc0 = { 4a b2 [2] 78 90 [2] 7e a5 [2] 50 a5 [2] 6f b9 }

  condition:
    any of them
}