rule TTP_XOR_WriteProcessMemory_6795 {
  strings:
    $key_6795 = { 30 e7 [2] 02 c5 [2] 04 f0 [2] 2a f0 [2] 15 ec }

  condition:
    any of them
}