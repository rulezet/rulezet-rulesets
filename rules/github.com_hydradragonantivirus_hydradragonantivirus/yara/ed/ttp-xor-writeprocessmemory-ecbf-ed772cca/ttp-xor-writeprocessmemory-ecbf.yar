rule TTP_XOR_WriteProcessMemory_ecbf {
  strings:
    $key_ecbf = { bb cd [2] 89 ef [2] 8f da [2] a1 da [2] 9e c6 }

  condition:
    any of them
}