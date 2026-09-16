rule TTP_XOR_WriteProcessMemory_3951 {
  strings:
    $key_3951 = { 6e 23 [2] 5c 01 [2] 5a 34 [2] 74 34 [2] 4b 28 }

  condition:
    any of them
}