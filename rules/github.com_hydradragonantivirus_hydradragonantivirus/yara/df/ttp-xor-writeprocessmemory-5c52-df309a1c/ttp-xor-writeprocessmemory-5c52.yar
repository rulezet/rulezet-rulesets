rule TTP_XOR_WriteProcessMemory_5c52 {
  strings:
    $key_5c52 = { 0b 20 [2] 39 02 [2] 3f 37 [2] 11 37 [2] 2e 2b }

  condition:
    any of them
}