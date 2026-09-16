rule TTP_XOR_WriteProcessMemory_e5bf {
  strings:
    $key_e5bf = { b2 cd [2] 80 ef [2] 86 da [2] a8 da [2] 97 c6 }

  condition:
    any of them
}