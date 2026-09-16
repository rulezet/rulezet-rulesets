rule TTP_XOR_WriteProcessMemory_4ec6 {
  strings:
    $key_4ec6 = { 19 b4 [2] 2b 96 [2] 2d a3 [2] 03 a3 [2] 3c bf }

  condition:
    any of them
}