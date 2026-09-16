rule TTP_XOR_WriteProcessMemory_66bf {
  strings:
    $key_66bf = { 31 cd [2] 03 ef [2] 05 da [2] 2b da [2] 14 c6 }

  condition:
    any of them
}