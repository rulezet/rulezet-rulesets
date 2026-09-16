rule TTP_XOR_WriteProcessMemory_e78a {
  strings:
    $key_e78a = { b0 f8 [2] 82 da [2] 84 ef [2] aa ef [2] 95 f3 }

  condition:
    any of them
}