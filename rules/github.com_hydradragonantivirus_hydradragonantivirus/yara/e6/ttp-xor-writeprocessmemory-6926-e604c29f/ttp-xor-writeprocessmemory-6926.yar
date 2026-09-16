rule TTP_XOR_WriteProcessMemory_6926 {
  strings:
    $key_6926 = { 3e 54 [2] 0c 76 [2] 0a 43 [2] 24 43 [2] 1b 5f }

  condition:
    any of them
}