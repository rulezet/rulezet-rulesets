rule TTP_XOR_WriteProcessMemory_7923 {
  strings:
    $key_7923 = { 2e 51 [2] 1c 73 [2] 1a 46 [2] 34 46 [2] 0b 5a }

  condition:
    any of them
}