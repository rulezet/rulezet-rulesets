rule TTP_XOR_WriteProcessMemory_6137 {
  strings:
    $key_6137 = { 36 45 [2] 04 67 [2] 02 52 [2] 2c 52 [2] 13 4e }

  condition:
    any of them
}