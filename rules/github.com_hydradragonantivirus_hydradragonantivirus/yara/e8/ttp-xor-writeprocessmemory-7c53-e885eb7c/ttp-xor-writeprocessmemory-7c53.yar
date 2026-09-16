rule TTP_XOR_WriteProcessMemory_7c53 {
  strings:
    $key_7c53 = { 2b 21 [2] 19 03 [2] 1f 36 [2] 31 36 [2] 0e 2a }

  condition:
    any of them
}