rule TTP_XOR_WriteProcessMemory_c8c7 {
  strings:
    $key_c8c7 = { 9f b5 [2] ad 97 [2] ab a2 [2] 85 a2 [2] ba be }

  condition:
    any of them
}