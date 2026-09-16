rule TTP_XOR_WriteProcessMemory_5457 {
  strings:
    $key_5457 = { 03 25 [2] 31 07 [2] 37 32 [2] 19 32 [2] 26 2e }

  condition:
    any of them
}