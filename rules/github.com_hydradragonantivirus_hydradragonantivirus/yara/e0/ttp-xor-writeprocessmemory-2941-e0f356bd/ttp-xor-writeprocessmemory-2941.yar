rule TTP_XOR_WriteProcessMemory_2941 {
  strings:
    $key_2941 = { 7e 33 [2] 4c 11 [2] 4a 24 [2] 64 24 [2] 5b 38 }

  condition:
    any of them
}