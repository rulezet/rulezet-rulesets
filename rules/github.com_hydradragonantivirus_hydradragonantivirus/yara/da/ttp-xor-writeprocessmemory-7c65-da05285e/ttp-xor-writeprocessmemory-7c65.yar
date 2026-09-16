rule TTP_XOR_WriteProcessMemory_7c65 {
  strings:
    $key_7c65 = { 2b 17 [2] 19 35 [2] 1f 00 [2] 31 00 [2] 0e 1c }

  condition:
    any of them
}