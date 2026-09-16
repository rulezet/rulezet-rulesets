rule TTP_XOR_WriteProcessMemory_6103 {
  strings:
    $key_6103 = { 36 71 [2] 04 53 [2] 02 66 [2] 2c 66 [2] 13 7a }

  condition:
    any of them
}