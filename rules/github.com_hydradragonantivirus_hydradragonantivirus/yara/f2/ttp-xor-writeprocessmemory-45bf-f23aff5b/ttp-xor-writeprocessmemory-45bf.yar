rule TTP_XOR_WriteProcessMemory_45bf {
  strings:
    $key_45bf = { 12 cd [2] 20 ef [2] 26 da [2] 08 da [2] 37 c6 }

  condition:
    any of them
}