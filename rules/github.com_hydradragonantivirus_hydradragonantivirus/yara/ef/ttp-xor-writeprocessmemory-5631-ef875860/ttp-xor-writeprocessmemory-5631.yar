rule TTP_XOR_WriteProcessMemory_5631 {
  strings:
    $key_5631 = { 01 43 [2] 33 61 [2] 35 54 [2] 1b 54 [2] 24 48 }

  condition:
    any of them
}