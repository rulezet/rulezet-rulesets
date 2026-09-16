rule TTP_XOR_WriteProcessMemory_0c30 {
  strings:
    $key_0c30 = { 5b 42 [2] 69 60 [2] 6f 55 [2] 41 55 [2] 7e 49 }

  condition:
    any of them
}