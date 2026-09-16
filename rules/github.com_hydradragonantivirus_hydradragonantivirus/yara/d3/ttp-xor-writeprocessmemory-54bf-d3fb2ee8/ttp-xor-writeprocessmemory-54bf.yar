rule TTP_XOR_WriteProcessMemory_54bf {
  strings:
    $key_54bf = { 03 cd [2] 31 ef [2] 37 da [2] 19 da [2] 26 c6 }

  condition:
    any of them
}