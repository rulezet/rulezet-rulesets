rule TTP_XOR_WriteProcessMemory_4904 {
  strings:
    $key_4904 = { 1e 76 [2] 2c 54 [2] 2a 61 [2] 04 61 [2] 3b 7d }

  condition:
    any of them
}