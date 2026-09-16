rule TTP_XOR_WriteProcessMemory_3803 {
  strings:
    $key_3803 = { 6f 71 [2] 5d 53 [2] 5b 66 [2] 75 66 [2] 4a 7a }

  condition:
    any of them
}