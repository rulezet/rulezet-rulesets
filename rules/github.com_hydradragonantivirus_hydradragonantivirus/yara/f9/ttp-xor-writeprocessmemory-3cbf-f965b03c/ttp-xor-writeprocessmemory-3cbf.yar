rule TTP_XOR_WriteProcessMemory_3cbf {
  strings:
    $key_3cbf = { 6b cd [2] 59 ef [2] 5f da [2] 71 da [2] 4e c6 }

  condition:
    any of them
}