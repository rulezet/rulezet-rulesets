rule TTP_XOR_WriteProcessMemory_f283 {
  strings:
    $key_f283 = { a5 f1 [2] 97 d3 [2] 91 e6 [2] bf e6 [2] 80 fa }

  condition:
    any of them
}