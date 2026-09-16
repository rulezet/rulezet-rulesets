rule TTP_XOR_WriteProcessMemory_eec6 {
  strings:
    $key_eec6 = { b9 b4 [2] 8b 96 [2] 8d a3 [2] a3 a3 [2] 9c bf }

  condition:
    any of them
}