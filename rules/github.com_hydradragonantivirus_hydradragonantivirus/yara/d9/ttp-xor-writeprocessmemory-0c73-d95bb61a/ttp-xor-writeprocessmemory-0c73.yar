rule TTP_XOR_WriteProcessMemory_0c73 {
  strings:
    $key_0c73 = { 5b 01 [2] 69 23 [2] 6f 16 [2] 41 16 [2] 7e 0a }

  condition:
    any of them
}