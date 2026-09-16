rule TTP_XOR_WriteProcessMemory_0c26 {
  strings:
    $key_0c26 = { 5b 54 [2] 69 76 [2] 6f 43 [2] 41 43 [2] 7e 5f }

  condition:
    any of them
}