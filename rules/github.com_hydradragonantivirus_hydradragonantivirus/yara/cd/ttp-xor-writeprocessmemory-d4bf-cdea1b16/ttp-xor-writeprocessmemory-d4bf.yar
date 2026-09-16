rule TTP_XOR_WriteProcessMemory_d4bf {
  strings:
    $key_d4bf = { 83 cd [2] b1 ef [2] b7 da [2] 99 da [2] a6 c6 }

  condition:
    any of them
}