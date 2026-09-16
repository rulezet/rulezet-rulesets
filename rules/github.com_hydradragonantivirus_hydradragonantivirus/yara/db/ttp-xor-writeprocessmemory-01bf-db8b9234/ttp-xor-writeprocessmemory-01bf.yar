rule TTP_XOR_WriteProcessMemory_01bf {
  strings:
    $key_01bf = { 56 cd [2] 64 ef [2] 62 da [2] 4c da [2] 73 c6 }

  condition:
    any of them
}