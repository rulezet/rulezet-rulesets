rule TTP_XOR_WriteProcessMemory_5af1 {
  strings:
    $key_5af1 = { 0d 83 [2] 3f a1 [2] 39 94 [2] 17 94 [2] 28 88 }

  condition:
    any of them
}