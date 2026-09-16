rule TTP_XOR_WriteProcessMemory_0ae1 {
  strings:
    $key_0ae1 = { 5d 93 [2] 6f b1 [2] 69 84 [2] 47 84 [2] 78 98 }

  condition:
    any of them
}