rule TTP_XOR_WriteProcessMemory_7943 {
  strings:
    $key_7943 = { 2e 31 [2] 1c 13 [2] 1a 26 [2] 34 26 [2] 0b 3a }

  condition:
    any of them
}