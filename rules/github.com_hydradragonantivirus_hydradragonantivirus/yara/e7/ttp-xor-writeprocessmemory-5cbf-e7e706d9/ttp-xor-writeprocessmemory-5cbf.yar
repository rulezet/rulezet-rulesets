rule TTP_XOR_WriteProcessMemory_5cbf {
  strings:
    $key_5cbf = { 0b cd [2] 39 ef [2] 3f da [2] 11 da [2] 2e c6 }

  condition:
    any of them
}