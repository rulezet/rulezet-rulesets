rule TTP_XOR_WriteProcessMemory_2af1 {
  strings:
    $key_2af1 = { 7d 83 [2] 4f a1 [2] 49 94 [2] 67 94 [2] 58 88 }

  condition:
    any of them
}