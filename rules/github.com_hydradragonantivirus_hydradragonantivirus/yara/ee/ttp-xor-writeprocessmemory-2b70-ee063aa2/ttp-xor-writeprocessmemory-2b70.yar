rule TTP_XOR_WriteProcessMemory_2b70 {
  strings:
    $key_2b70 = { 7c 02 [2] 4e 20 [2] 48 15 [2] 66 15 [2] 59 09 }

  condition:
    any of them
}