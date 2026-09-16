rule TTP_XOR_WriteProcessMemory_6bcd {
  strings:
    $key_6bcd = { 3c bf [2] 0e 9d [2] 08 a8 [2] 26 a8 [2] 19 b4 }

  condition:
    any of them
}