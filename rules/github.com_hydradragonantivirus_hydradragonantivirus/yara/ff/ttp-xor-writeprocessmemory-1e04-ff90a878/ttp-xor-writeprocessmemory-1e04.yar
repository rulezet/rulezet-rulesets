rule TTP_XOR_WriteProcessMemory_1e04 {
  strings:
    $key_1e04 = { 49 76 [2] 7b 54 [2] 7d 61 [2] 53 61 [2] 6c 7d }

  condition:
    any of them
}