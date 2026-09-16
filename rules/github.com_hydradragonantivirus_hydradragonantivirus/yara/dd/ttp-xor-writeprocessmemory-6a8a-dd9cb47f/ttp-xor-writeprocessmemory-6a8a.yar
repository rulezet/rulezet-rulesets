rule TTP_XOR_WriteProcessMemory_6a8a {
  strings:
    $key_6a8a = { 3d f8 [2] 0f da [2] 09 ef [2] 27 ef [2] 18 f3 }

  condition:
    any of them
}