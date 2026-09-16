rule TTP_XOR_WriteProcessMemory_2e24 {
  strings:
    $key_2e24 = { 79 56 [2] 4b 74 [2] 4d 41 [2] 63 41 [2] 5c 5d }

  condition:
    any of them
}