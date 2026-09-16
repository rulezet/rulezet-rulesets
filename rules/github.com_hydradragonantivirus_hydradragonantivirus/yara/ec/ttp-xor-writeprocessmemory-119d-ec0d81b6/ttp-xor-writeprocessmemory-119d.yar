rule TTP_XOR_WriteProcessMemory_119d {
  strings:
    $key_119d = { 46 ef [2] 74 cd [2] 72 f8 [2] 5c f8 [2] 63 e4 }

  condition:
    any of them
}