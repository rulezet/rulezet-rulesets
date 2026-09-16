rule TTP_XOR_WriteProcessMemory_3e04 {
  strings:
    $key_3e04 = { 69 76 [2] 5b 54 [2] 5d 61 [2] 73 61 [2] 4c 7d }

  condition:
    any of them
}