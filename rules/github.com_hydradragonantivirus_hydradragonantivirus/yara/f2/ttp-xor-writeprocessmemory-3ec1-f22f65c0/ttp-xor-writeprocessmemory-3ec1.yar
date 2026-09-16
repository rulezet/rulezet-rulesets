rule TTP_XOR_WriteProcessMemory_3ec1 {
  strings:
    $key_3ec1 = { 69 b3 [2] 5b 91 [2] 5d a4 [2] 73 a4 [2] 4c b8 }

  condition:
    any of them
}