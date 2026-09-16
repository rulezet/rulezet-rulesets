rule TTP_XOR_WriteProcessMemory_6907 {
  strings:
    $key_6907 = { 3e 75 [2] 0c 57 [2] 0a 62 [2] 24 62 [2] 1b 7e }

  condition:
    any of them
}