rule TTP_XOR_WriteProcessMemory_4786 {
  strings:
    $key_4786 = { 10 f4 [2] 22 d6 [2] 24 e3 [2] 0a e3 [2] 35 ff }

  condition:
    any of them
}