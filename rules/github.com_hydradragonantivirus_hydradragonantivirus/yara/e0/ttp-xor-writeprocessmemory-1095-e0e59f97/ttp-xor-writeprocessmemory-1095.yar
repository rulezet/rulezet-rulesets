rule TTP_XOR_WriteProcessMemory_1095 {
  strings:
    $key_1095 = { 47 e7 [2] 75 c5 [2] 73 f0 [2] 5d f0 [2] 62 ec }

  condition:
    any of them
}