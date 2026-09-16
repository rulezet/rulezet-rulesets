rule TTP_XOR_WriteProcessMemory_2c54 {
  strings:
    $key_2c54 = { 7b 26 [2] 49 04 [2] 4f 31 [2] 61 31 [2] 5e 2d }

  condition:
    any of them
}