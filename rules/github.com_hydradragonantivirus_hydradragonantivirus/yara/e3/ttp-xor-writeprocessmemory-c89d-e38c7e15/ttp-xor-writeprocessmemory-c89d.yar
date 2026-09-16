rule TTP_XOR_WriteProcessMemory_c89d {
  strings:
    $key_c89d = { 9f ef [2] ad cd [2] ab f8 [2] 85 f8 [2] ba e4 }

  condition:
    any of them
}