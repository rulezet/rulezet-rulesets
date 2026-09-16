rule TTP_XOR_WriteProcessMemory_318a {
  strings:
    $key_318a = { 66 f8 [2] 54 da [2] 52 ef [2] 7c ef [2] 43 f3 }

  condition:
    any of them
}