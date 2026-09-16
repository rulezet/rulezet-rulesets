rule TTP_XOR_WriteProcessMemory_394d {
  strings:
    $key_394d = { 6e 3f [2] 5c 1d [2] 5a 28 [2] 74 28 [2] 4b 34 }

  condition:
    any of them
}