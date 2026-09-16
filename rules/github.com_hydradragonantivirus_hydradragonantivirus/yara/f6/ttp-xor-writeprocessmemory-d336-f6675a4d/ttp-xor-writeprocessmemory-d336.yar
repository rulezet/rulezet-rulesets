rule TTP_XOR_WriteProcessMemory_d336 {
  strings:
    $key_d336 = { 84 44 [2] b6 66 [2] b0 53 [2] 9e 53 [2] a1 4f }

  condition:
    any of them
}