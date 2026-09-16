rule TTP_XOR_WriteProcessMemory_7ec1 {
  strings:
    $key_7ec1 = { 29 b3 [2] 1b 91 [2] 1d a4 [2] 33 a4 [2] 0c b8 }

  condition:
    any of them
}