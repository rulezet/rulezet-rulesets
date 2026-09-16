rule TTP_XOR_WriteProcessMemory_f9c6 {
  strings:
    $key_f9c6 = { ae b4 [2] 9c 96 [2] 9a a3 [2] b4 a3 [2] 8b bf }

  condition:
    any of them
}