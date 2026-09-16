rule TTP_XOR_WriteProcessMemory_3155 {
  strings:
    $key_3155 = { 66 27 [2] 54 05 [2] 52 30 [2] 7c 30 [2] 43 2c }

  condition:
    any of them
}