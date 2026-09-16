rule TTP_XOR_WriteProcessMemory_c8c4 {
  strings:
    $key_c8c4 = { 9f b6 [2] ad 94 [2] ab a1 [2] 85 a1 [2] ba bd }

  condition:
    any of them
}