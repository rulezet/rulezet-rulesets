rule TTP_XOR_WriteProcessMemory_1f03 {
  strings:
    $key_1f03 = { 48 71 [2] 7a 53 [2] 7c 66 [2] 52 66 [2] 6d 7a }

  condition:
    any of them
}