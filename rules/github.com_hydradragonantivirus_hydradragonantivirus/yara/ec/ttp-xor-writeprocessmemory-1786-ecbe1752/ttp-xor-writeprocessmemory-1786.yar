rule TTP_XOR_WriteProcessMemory_1786 {
  strings:
    $key_1786 = { 40 f4 [2] 72 d6 [2] 74 e3 [2] 5a e3 [2] 65 ff }

  condition:
    any of them
}