rule TTP_XOR_WriteProcessMemory_7c37 {
  strings:
    $key_7c37 = { 2b 45 [2] 19 67 [2] 1f 52 [2] 31 52 [2] 0e 4e }

  condition:
    any of them
}