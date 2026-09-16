rule TTP_XOR_WriteProcessMemory_1407 {
  strings:
    $key_1407 = { 43 75 [2] 71 57 [2] 77 62 [2] 59 62 [2] 66 7e }

  condition:
    any of them
}