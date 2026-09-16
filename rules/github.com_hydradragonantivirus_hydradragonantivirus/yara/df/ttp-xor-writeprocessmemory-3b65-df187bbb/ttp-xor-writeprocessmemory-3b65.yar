rule TTP_XOR_WriteProcessMemory_3b65 {
  strings:
    $key_3b65 = { 6c 17 [2] 5e 35 [2] 58 00 [2] 76 00 [2] 49 1c }

  condition:
    any of them
}