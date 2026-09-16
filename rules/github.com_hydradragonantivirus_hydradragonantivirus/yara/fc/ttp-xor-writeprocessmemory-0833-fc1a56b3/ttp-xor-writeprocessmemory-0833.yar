rule TTP_XOR_WriteProcessMemory_0833 {
  strings:
    $key_0833 = { 5f 41 [2] 6d 63 [2] 6b 56 [2] 45 56 [2] 7a 4a }

  condition:
    any of them
}