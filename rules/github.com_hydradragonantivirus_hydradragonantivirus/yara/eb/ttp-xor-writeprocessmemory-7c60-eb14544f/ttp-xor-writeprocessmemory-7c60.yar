rule TTP_XOR_WriteProcessMemory_7c60 {
  strings:
    $key_7c60 = { 2b 12 [2] 19 30 [2] 1f 05 [2] 31 05 [2] 0e 19 }

  condition:
    any of them
}