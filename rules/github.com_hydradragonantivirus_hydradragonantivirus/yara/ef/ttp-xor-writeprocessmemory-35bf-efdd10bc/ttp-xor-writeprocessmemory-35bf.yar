rule TTP_XOR_WriteProcessMemory_35bf {
  strings:
    $key_35bf = { 62 cd [2] 50 ef [2] 56 da [2] 78 da [2] 47 c6 }

  condition:
    any of them
}