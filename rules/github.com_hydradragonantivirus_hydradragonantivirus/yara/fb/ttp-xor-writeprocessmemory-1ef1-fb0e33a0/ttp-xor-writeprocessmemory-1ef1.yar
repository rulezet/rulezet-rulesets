rule TTP_XOR_WriteProcessMemory_1ef1 {
  strings:
    $key_1ef1 = { 49 83 [2] 7b a1 [2] 7d 94 [2] 53 94 [2] 6c 88 }

  condition:
    any of them
}