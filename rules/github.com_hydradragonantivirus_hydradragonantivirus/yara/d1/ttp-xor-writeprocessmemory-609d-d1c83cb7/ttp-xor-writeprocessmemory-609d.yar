rule TTP_XOR_WriteProcessMemory_609d {
  strings:
    $key_609d = { 37 ef [2] 05 cd [2] 03 f8 [2] 2d f8 [2] 12 e4 }

  condition:
    any of them
}