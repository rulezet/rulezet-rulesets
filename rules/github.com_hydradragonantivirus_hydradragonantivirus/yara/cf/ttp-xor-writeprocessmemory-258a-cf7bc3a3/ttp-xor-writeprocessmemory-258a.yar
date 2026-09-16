rule TTP_XOR_WriteProcessMemory_258a {
  strings:
    $key_258a = { 72 f8 [2] 40 da [2] 46 ef [2] 68 ef [2] 57 f3 }

  condition:
    any of them
}