rule TTP_XOR_WriteProcessMemory_5737 {
  strings:
    $key_5737 = { 00 45 [2] 32 67 [2] 34 52 [2] 1a 52 [2] 25 4e }

  condition:
    any of them
}