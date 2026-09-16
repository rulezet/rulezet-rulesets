rule TTP_XOR_WriteProcessMemory_3955 {
  strings:
    $key_3955 = { 6e 27 [2] 5c 05 [2] 5a 30 [2] 74 30 [2] 4b 2c }

  condition:
    any of them
}