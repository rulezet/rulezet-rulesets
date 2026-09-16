rule TTP_XOR_WriteProcessMemory_3e62 {
  strings:
    $key_3e62 = { 69 10 [2] 5b 32 [2] 5d 07 [2] 73 07 [2] 4c 1b }

  condition:
    any of them
}