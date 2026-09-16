rule TTP_XOR_WriteProcessMemory_4403 {
  strings:
    $key_4403 = { 13 71 [2] 21 53 [2] 27 66 [2] 09 66 [2] 36 7a }

  condition:
    any of them
}