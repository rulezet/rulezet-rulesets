rule TTP_XOR_WriteProcessMemory_63bf {
  strings:
    $key_63bf = { 34 cd [2] 06 ef [2] 00 da [2] 2e da [2] 11 c6 }

  condition:
    any of them
}