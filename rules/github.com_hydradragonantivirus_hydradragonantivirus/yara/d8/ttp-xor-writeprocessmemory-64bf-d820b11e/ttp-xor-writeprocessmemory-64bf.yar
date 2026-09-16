rule TTP_XOR_WriteProcessMemory_64bf {
  strings:
    $key_64bf = { 33 cd [2] 01 ef [2] 07 da [2] 29 da [2] 16 c6 }

  condition:
    any of them
}