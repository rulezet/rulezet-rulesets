rule TTP_XOR_WriteProcessMemory_4c13 {
  strings:
    $key_4c13 = { 1b 61 [2] 29 43 [2] 2f 76 [2] 01 76 [2] 3e 6a }

  condition:
    any of them
}