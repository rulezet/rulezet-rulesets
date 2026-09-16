rule TTP_XOR_WriteProcessMemory_7e26 {
  strings:
    $key_7e26 = { 29 54 [2] 1b 76 [2] 1d 43 [2] 33 43 [2] 0c 5f }

  condition:
    any of them
}