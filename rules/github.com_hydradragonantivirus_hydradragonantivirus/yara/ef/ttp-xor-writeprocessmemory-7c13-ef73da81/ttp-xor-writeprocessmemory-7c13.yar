rule TTP_XOR_WriteProcessMemory_7c13 {
  strings:
    $key_7c13 = { 2b 61 [2] 19 43 [2] 1f 76 [2] 31 76 [2] 0e 6a }

  condition:
    any of them
}