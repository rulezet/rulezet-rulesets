rule TTP_XOR_WriteProcessMemory_e48a {
  strings:
    $key_e48a = { b3 f8 [2] 81 da [2] 87 ef [2] a9 ef [2] 96 f3 }

  condition:
    any of them
}