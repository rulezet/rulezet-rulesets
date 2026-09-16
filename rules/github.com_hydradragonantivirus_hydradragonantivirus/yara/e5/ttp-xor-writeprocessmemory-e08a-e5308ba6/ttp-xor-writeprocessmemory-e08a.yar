rule TTP_XOR_WriteProcessMemory_e08a {
  strings:
    $key_e08a = { b7 f8 [2] 85 da [2] 83 ef [2] ad ef [2] 92 f3 }

  condition:
    any of them
}