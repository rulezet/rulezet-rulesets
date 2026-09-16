rule TTP_XOR_WriteProcessMemory_2207 {
  strings:
    $key_2207 = { 75 75 [2] 47 57 [2] 41 62 [2] 6f 62 [2] 50 7e }

  condition:
    any of them
}