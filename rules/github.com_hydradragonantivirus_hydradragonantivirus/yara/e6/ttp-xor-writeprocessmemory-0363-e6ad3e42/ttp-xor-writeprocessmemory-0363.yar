rule TTP_XOR_WriteProcessMemory_0363 {
  strings:
    $key_0363 = { 54 11 [2] 66 33 [2] 60 06 [2] 4e 06 [2] 71 1a }

  condition:
    any of them
}