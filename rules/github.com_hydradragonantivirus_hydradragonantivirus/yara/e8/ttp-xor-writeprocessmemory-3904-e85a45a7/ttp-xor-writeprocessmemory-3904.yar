rule TTP_XOR_WriteProcessMemory_3904 {
  strings:
    $key_3904 = { 6e 76 [2] 5c 54 [2] 5a 61 [2] 74 61 [2] 4b 7d }

  condition:
    any of them
}