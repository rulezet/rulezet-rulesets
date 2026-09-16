rule TTP_XOR_WriteProcessMemory_168a {
  strings:
    $key_168a = { 41 f8 [2] 73 da [2] 75 ef [2] 5b ef [2] 64 f3 }

  condition:
    any of them
}