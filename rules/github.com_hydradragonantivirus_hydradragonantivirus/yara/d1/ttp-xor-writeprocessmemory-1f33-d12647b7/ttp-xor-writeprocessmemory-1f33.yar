rule TTP_XOR_WriteProcessMemory_1f33 {
  strings:
    $key_1f33 = { 48 41 [2] 7a 63 [2] 7c 56 [2] 52 56 [2] 6d 4a }

  condition:
    any of them
}