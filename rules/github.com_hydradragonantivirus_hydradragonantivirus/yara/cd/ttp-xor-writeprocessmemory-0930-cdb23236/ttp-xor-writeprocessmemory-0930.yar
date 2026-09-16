rule TTP_XOR_WriteProcessMemory_0930 {
  strings:
    $key_0930 = { 5e 42 [2] 6c 60 [2] 6a 55 [2] 44 55 [2] 7b 49 }

  condition:
    any of them
}