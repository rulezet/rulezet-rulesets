rule TTP_XOR_WriteProcessMemory_7c07 {
  strings:
    $key_7c07 = { 2b 75 [2] 19 57 [2] 1f 62 [2] 31 62 [2] 0e 7e }

  condition:
    any of them
}