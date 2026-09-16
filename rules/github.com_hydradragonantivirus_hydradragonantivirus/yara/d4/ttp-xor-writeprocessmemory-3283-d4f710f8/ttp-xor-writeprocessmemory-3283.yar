rule TTP_XOR_WriteProcessMemory_3283 {
  strings:
    $key_3283 = { 65 f1 [2] 57 d3 [2] 51 e6 [2] 7f e6 [2] 40 fa }

  condition:
    any of them
}