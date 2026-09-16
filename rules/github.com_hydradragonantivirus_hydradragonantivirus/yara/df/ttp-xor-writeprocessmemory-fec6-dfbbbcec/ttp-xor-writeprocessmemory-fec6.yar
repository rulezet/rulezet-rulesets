rule TTP_XOR_WriteProcessMemory_fec6 {
  strings:
    $key_fec6 = { a9 b4 [2] 9b 96 [2] 9d a3 [2] b3 a3 [2] 8c bf }

  condition:
    any of them
}