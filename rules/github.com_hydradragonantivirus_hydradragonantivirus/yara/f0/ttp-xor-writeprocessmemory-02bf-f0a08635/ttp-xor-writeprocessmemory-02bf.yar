rule TTP_XOR_WriteProcessMemory_02bf {
  strings:
    $key_02bf = { 55 cd [2] 67 ef [2] 61 da [2] 4f da [2] 70 c6 }

  condition:
    any of them
}