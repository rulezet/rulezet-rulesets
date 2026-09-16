rule TTP_XOR_WriteProcessMemory_2ef0 {
  strings:
    $key_2ef0 = { 79 82 [2] 4b a0 [2] 4d 95 [2] 63 95 [2] 5c 89 }

  condition:
    any of them
}