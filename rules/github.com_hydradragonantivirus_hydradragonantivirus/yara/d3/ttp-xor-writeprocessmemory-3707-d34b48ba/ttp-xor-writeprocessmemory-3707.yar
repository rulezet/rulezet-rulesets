rule TTP_XOR_WriteProcessMemory_3707 {
  strings:
    $key_3707 = { 60 75 [2] 52 57 [2] 54 62 [2] 7a 62 [2] 45 7e }

  condition:
    any of them
}