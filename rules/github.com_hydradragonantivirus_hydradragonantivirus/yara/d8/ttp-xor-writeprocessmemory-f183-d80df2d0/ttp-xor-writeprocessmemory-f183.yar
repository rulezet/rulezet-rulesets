rule TTP_XOR_WriteProcessMemory_f183 {
  strings:
    $key_f183 = { a6 f1 [2] 94 d3 [2] 92 e6 [2] bc e6 [2] 83 fa }

  condition:
    any of them
}