rule TTP_XOR_WriteProcessMemory_5d70 {
  strings:
    $key_5d70 = { 0a 02 [2] 38 20 [2] 3e 15 [2] 10 15 [2] 2f 09 }

  condition:
    any of them
}