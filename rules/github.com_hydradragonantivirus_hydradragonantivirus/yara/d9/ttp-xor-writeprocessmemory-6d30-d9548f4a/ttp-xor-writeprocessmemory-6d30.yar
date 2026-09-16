rule TTP_XOR_WriteProcessMemory_6d30 {
  strings:
    $key_6d30 = { 3a 42 [2] 08 60 [2] 0e 55 [2] 20 55 [2] 1f 49 }

  condition:
    any of them
}