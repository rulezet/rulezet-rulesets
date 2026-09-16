rule TTP_XOR_WriteProcessMemory_6754 {
  strings:
    $key_6754 = { 30 26 [2] 02 04 [2] 04 31 [2] 2a 31 [2] 15 2d }

  condition:
    any of them
}