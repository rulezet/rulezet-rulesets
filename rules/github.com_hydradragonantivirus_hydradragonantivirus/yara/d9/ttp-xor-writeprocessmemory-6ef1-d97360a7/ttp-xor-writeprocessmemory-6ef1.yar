rule TTP_XOR_WriteProcessMemory_6ef1 {
  strings:
    $key_6ef1 = { 39 83 [2] 0b a1 [2] 0d 94 [2] 23 94 [2] 1c 88 }

  condition:
    any of them
}