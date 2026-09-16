rule TTP_XOR_WriteProcessMemory_7403 {
  strings:
    $key_7403 = { 23 71 [2] 11 53 [2] 17 66 [2] 39 66 [2] 06 7a }

  condition:
    any of them
}