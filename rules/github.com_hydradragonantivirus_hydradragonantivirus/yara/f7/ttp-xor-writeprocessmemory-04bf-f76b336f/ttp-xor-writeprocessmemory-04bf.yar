rule TTP_XOR_WriteProcessMemory_04bf {
  strings:
    $key_04bf = { 53 cd [2] 61 ef [2] 67 da [2] 49 da [2] 76 c6 }

  condition:
    any of them
}