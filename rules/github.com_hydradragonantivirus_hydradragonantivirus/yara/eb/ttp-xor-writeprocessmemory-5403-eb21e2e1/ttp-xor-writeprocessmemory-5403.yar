rule TTP_XOR_WriteProcessMemory_5403 {
  strings:
    $key_5403 = { 03 71 [2] 31 53 [2] 37 66 [2] 19 66 [2] 26 7a }

  condition:
    any of them
}