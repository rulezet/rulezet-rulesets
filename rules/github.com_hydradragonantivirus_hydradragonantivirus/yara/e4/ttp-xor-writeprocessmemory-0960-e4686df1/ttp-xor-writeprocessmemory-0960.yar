rule TTP_XOR_WriteProcessMemory_0960 {
  strings:
    $key_0960 = { 5e 12 [2] 6c 30 [2] 6a 05 [2] 44 05 [2] 7b 19 }

  condition:
    any of them
}