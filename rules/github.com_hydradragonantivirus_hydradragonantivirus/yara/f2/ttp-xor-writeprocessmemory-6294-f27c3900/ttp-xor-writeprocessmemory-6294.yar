rule TTP_XOR_WriteProcessMemory_6294 {
  strings:
    $key_6294 = { 35 e6 [2] 07 c4 [2] 01 f1 [2] 2f f1 [2] 10 ed }

  condition:
    any of them
}