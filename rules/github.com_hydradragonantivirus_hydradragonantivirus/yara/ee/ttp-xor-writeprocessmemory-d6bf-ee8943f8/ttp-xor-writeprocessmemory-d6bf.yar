rule TTP_XOR_WriteProcessMemory_d6bf {
  strings:
    $key_d6bf = { 81 cd [2] b3 ef [2] b5 da [2] 9b da [2] a4 c6 }

  condition:
    any of them
}