rule TTP_XOR_WriteProcessMemory_7ae1 {
  strings:
    $key_7ae1 = { 2d 93 [2] 1f b1 [2] 19 84 [2] 37 84 [2] 08 98 }

  condition:
    any of them
}