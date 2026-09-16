rule TTP_XOR_WriteProcessMemory_44bf {
  strings:
    $key_44bf = { 13 cd [2] 21 ef [2] 27 da [2] 09 da [2] 36 c6 }

  condition:
    any of them
}