rule TTP_XOR_WriteProcessMemory_3ec6 {
  strings:
    $key_3ec6 = { 69 b4 [2] 5b 96 [2] 5d a3 [2] 73 a3 [2] 4c bf }

  condition:
    any of them
}