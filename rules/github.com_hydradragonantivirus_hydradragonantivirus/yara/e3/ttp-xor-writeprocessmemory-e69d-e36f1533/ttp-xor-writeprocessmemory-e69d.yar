rule TTP_XOR_WriteProcessMemory_e69d {
  strings:
    $key_e69d = { b1 ef [2] 83 cd [2] 85 f8 [2] ab f8 [2] 94 e4 }

  condition:
    any of them
}