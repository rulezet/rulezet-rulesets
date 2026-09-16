rule TTP_XOR_WriteProcessMemory_3953 {
  strings:
    $key_3953 = { 6e 21 [2] 5c 03 [2] 5a 36 [2] 74 36 [2] 4b 2a }

  condition:
    any of them
}