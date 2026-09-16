rule TTP_XOR_WriteProcessMemory_12bf {
  strings:
    $key_12bf = { 45 cd [2] 77 ef [2] 71 da [2] 5f da [2] 60 c6 }

  condition:
    any of them
}