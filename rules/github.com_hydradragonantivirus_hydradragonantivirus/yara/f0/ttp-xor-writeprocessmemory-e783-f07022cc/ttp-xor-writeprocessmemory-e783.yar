rule TTP_XOR_WriteProcessMemory_e783 {
  strings:
    $key_e783 = { b0 f1 [2] 82 d3 [2] 84 e6 [2] aa e6 [2] 95 fa }

  condition:
    any of them
}