rule TTP_XOR_WriteProcessMemory_6c91 {
  strings:
    $key_6c91 = { 3b e3 [2] 09 c1 [2] 0f f4 [2] 21 f4 [2] 1e e8 }

  condition:
    any of them
}