rule TTP_XOR_WriteProcessMemory_d0c3 {
  strings:
    $key_d0c3 = { 87 b1 [2] b5 93 [2] b3 a6 [2] 9d a6 [2] a2 ba }

  condition:
    any of them
}