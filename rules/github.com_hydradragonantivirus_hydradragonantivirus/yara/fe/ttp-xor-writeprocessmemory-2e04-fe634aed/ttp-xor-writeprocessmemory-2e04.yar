rule TTP_XOR_WriteProcessMemory_2e04 {
  strings:
    $key_2e04 = { 79 76 [2] 4b 54 [2] 4d 61 [2] 63 61 [2] 5c 7d }

  condition:
    any of them
}