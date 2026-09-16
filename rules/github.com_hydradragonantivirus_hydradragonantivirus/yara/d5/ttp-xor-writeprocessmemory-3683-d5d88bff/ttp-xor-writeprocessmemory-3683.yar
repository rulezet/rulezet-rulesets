rule TTP_XOR_WriteProcessMemory_3683 {
  strings:
    $key_3683 = { 61 f1 [2] 53 d3 [2] 55 e6 [2] 7b e6 [2] 44 fa }

  condition:
    any of them
}