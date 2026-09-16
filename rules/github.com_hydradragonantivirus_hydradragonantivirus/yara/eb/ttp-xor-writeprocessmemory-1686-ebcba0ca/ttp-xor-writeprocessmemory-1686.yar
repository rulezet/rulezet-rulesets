rule TTP_XOR_WriteProcessMemory_1686 {
  strings:
    $key_1686 = { 41 f4 [2] 73 d6 [2] 75 e3 [2] 5b e3 [2] 64 ff }

  condition:
    any of them
}