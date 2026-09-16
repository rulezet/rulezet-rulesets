rule TTP_XOR_WriteProcessMemory_5639 {
  strings:
    $key_5639 = { 01 4b [2] 33 69 [2] 35 5c [2] 1b 5c [2] 24 40 }

  condition:
    any of them
}