rule TTP_XOR_WriteProcessMemory_7813 {
  strings:
    $key_7813 = { 2f 61 [2] 1d 43 [2] 1b 76 [2] 35 76 [2] 0a 6a }

  condition:
    any of them
}