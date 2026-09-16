rule TTP_XOR_WriteProcessMemory_d701 {
  strings:
    $key_d701 = { 80 73 [2] b2 51 [2] b4 64 [2] 9a 64 [2] a5 78 }

  condition:
    any of them
}