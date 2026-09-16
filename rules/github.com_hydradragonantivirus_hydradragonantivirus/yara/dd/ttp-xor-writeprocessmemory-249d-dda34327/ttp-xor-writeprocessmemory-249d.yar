rule TTP_XOR_WriteProcessMemory_249d {
  strings:
    $key_249d = { 73 ef [2] 41 cd [2] 47 f8 [2] 69 f8 [2] 56 e4 }

  condition:
    any of them
}