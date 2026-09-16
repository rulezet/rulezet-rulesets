rule TTP_XOR_WriteProcessMemory_0c10 {
  strings:
    $key_0c10 = { 5b 62 [2] 69 40 [2] 6f 75 [2] 41 75 [2] 7e 69 }

  condition:
    any of them
}