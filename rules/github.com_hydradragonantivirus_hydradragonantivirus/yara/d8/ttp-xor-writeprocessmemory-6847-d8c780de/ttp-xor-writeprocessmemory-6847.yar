rule TTP_XOR_WriteProcessMemory_6847 {
  strings:
    $key_6847 = { 3f 35 [2] 0d 17 [2] 0b 22 [2] 25 22 [2] 1a 3e }

  condition:
    any of them
}