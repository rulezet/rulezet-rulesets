rule TTP_XOR_WriteProcessMemory_6403 {
  strings:
    $key_6403 = { 33 71 [2] 01 53 [2] 07 66 [2] 29 66 [2] 16 7a }

  condition:
    any of them
}