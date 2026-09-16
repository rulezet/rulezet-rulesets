rule TTP_XOR_WriteProcessMemory_2b26 {
  strings:
    $key_2b26 = { 7c 54 [2] 4e 76 [2] 48 43 [2] 66 43 [2] 59 5f }

  condition:
    any of them
}