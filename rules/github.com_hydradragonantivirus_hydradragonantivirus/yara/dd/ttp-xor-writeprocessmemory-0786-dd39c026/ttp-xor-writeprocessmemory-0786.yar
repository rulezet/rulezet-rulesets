rule TTP_XOR_WriteProcessMemory_0786 {
  strings:
    $key_0786 = { 50 f4 [2] 62 d6 [2] 64 e3 [2] 4a e3 [2] 75 ff }

  condition:
    any of them
}