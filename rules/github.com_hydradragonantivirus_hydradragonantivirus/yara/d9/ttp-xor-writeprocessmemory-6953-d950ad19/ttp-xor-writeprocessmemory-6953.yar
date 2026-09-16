rule TTP_XOR_WriteProcessMemory_6953 {
  strings:
    $key_6953 = { 3e 21 [2] 0c 03 [2] 0a 36 [2] 24 36 [2] 1b 2a }

  condition:
    any of them
}