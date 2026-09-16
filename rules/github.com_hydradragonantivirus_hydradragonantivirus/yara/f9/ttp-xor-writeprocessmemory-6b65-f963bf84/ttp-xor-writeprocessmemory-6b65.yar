rule TTP_XOR_WriteProcessMemory_6b65 {
  strings:
    $key_6b65 = { 3c 17 [2] 0e 35 [2] 08 00 [2] 26 00 [2] 19 1c }

  condition:
    any of them
}