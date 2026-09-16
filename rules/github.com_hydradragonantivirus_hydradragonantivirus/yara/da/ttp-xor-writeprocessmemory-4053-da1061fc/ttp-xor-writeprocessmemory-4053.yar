rule TTP_XOR_WriteProcessMemory_4053 {
  strings:
    $key_4053 = { 17 21 [2] 25 03 [2] 23 36 [2] 0d 36 [2] 32 2a }

  condition:
    any of them
}