rule TTP_XOR_WriteProcessMemory_46bf {
  strings:
    $key_46bf = { 11 cd [2] 23 ef [2] 25 da [2] 0b da [2] 34 c6 }

  condition:
    any of them
}