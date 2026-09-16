rule TTP_XOR_WriteProcessMemory_c6bf {
  strings:
    $key_c6bf = { 91 cd [2] a3 ef [2] a5 da [2] 8b da [2] b4 c6 }

  condition:
    any of them
}