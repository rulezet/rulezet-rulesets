rule TTP_XOR_WriteProcessMemory_28c4 {
  strings:
    $key_28c4 = { 7f b6 [2] 4d 94 [2] 4b a1 [2] 65 a1 [2] 5a bd }

  condition:
    any of them
}