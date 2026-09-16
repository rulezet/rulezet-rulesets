rule TTP_XOR_WriteProcessMemory_5b30 {
  strings:
    $key_5b30 = { 0c 42 [2] 3e 60 [2] 38 55 [2] 16 55 [2] 29 49 }

  condition:
    any of them
}