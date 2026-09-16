rule TTP_XOR_WriteProcessMemory_5922 {
  strings:
    $key_5922 = { 0e 50 [2] 3c 72 [2] 3a 47 [2] 14 47 [2] 2b 5b }

  condition:
    any of them
}