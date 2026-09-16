rule TTP_XOR_WriteProcessMemory_fa8a {
  strings:
    $key_fa8a = { ad f8 [2] 9f da [2] 99 ef [2] b7 ef [2] 88 f3 }

  condition:
    any of them
}