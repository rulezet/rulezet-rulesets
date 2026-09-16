rule TTP_XOR_WriteProcessMemory_4e03 {
  strings:
    $key_4e03 = { 19 71 [2] 2b 53 [2] 2d 66 [2] 03 66 [2] 3c 7a }

  condition:
    any of them
}