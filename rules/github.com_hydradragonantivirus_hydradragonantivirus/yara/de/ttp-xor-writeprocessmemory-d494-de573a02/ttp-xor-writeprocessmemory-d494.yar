rule TTP_XOR_WriteProcessMemory_d494 {
  strings:
    $key_d494 = { 83 e6 [2] b1 c4 [2] b7 f1 [2] 99 f1 [2] a6 ed }

  condition:
    any of them
}