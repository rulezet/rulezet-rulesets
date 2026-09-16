rule TTP_XOR_WriteProcessMemory_6173 {
  strings:
    $key_6173 = { 36 01 [2] 04 23 [2] 02 16 [2] 2c 16 [2] 13 0a }

  condition:
    any of them
}