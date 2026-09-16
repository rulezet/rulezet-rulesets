rule TTP_XOR_WriteProcessMemory_0ec1 {
  strings:
    $key_0ec1 = { 59 b3 [2] 6b 91 [2] 6d a4 [2] 43 a4 [2] 7c b8 }

  condition:
    any of them
}