rule TTP_XOR_WriteProcessMemory_e09d {
  strings:
    $key_e09d = { b7 ef [2] 85 cd [2] 83 f8 [2] ad f8 [2] 92 e4 }

  condition:
    any of them
}