rule TTP_XOR_WriteProcessMemory_6b70 {
  strings:
    $key_6b70 = { 3c 02 [2] 0e 20 [2] 08 15 [2] 26 15 [2] 19 09 }

  condition:
    any of them
}