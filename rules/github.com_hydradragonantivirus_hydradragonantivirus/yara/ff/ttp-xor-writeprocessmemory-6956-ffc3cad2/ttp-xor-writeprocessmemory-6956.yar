rule TTP_XOR_WriteProcessMemory_6956 {
  strings:
    $key_6956 = { 3e 24 [2] 0c 06 [2] 0a 33 [2] 24 33 [2] 1b 2f }

  condition:
    any of them
}