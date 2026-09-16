rule TTP_XOR_WriteProcessMemory_0097 {
  strings:
    $key_0097 = { 57 e5 [2] 65 c7 [2] 63 f2 [2] 4d f2 [2] 72 ee }

  condition:
    any of them
}