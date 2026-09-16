rule TTP_XOR_WriteProcessMemory_1d03 {
  strings:
    $key_1d03 = { 4a 71 [2] 78 53 [2] 7e 66 [2] 50 66 [2] 6f 7a }

  condition:
    any of them
}