rule TTP_XOR_WriteProcessMemory_2407 {
  strings:
    $key_2407 = { 73 75 [2] 41 57 [2] 47 62 [2] 69 62 [2] 56 7e }

  condition:
    any of them
}