rule TTP_XOR_WriteProcessMemory_d013 {
  strings:
    $key_d013 = { 87 61 [2] b5 43 [2] b3 76 [2] 9d 76 [2] a2 6a }

  condition:
    any of them
}