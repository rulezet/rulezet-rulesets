rule TTP_XOR_WriteProcessMemory_f383 {
  strings:
    $key_f383 = { a4 f1 [2] 96 d3 [2] 90 e6 [2] be e6 [2] 81 fa }

  condition:
    any of them
}