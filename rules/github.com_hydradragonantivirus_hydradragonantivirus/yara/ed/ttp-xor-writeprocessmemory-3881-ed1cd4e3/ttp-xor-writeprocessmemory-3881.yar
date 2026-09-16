rule TTP_XOR_WriteProcessMemory_3881 {
  strings:
    $key_3881 = { 6f f3 [2] 5d d1 [2] 5b e4 [2] 75 e4 [2] 4a f8 }

  condition:
    any of them
}