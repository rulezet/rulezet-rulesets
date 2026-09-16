rule TTP_XOR_WriteProcessMemory_51bf {
  strings:
    $key_51bf = { 06 cd [2] 34 ef [2] 32 da [2] 1c da [2] 23 c6 }

  condition:
    any of them
}