rule TTP_XOR_WriteProcessMemory_268a {
  strings:
    $key_268a = { 71 f8 [2] 43 da [2] 45 ef [2] 6b ef [2] 54 f3 }

  condition:
    any of them
}