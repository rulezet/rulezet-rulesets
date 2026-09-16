rule TTP_XOR_WriteProcessMemory_2d30 {
  strings:
    $key_2d30 = { 7a 42 [2] 48 60 [2] 4e 55 [2] 60 55 [2] 5f 49 }

  condition:
    any of them
}