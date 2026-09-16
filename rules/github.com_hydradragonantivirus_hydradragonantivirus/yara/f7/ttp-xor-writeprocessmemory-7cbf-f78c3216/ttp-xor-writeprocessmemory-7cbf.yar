rule TTP_XOR_WriteProcessMemory_7cbf {
  strings:
    $key_7cbf = { 2b cd [2] 19 ef [2] 1f da [2] 31 da [2] 0e c6 }

  condition:
    any of them
}