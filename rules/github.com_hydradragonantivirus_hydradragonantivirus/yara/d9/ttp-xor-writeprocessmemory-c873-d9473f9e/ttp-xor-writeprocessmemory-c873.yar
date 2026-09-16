rule TTP_XOR_WriteProcessMemory_c873 {
  strings:
    $key_c873 = { 9f 01 [2] ad 23 [2] ab 16 [2] 85 16 [2] ba 0a }

  condition:
    any of them
}