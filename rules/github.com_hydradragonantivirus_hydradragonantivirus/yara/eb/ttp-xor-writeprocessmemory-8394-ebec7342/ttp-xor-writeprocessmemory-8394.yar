rule TTP_XOR_WriteProcessMemory_8394 {
  strings:
    $key_8394 = { d4 e6 [2] e6 c4 [2] e0 f1 [2] ce f1 [2] f1 ed }

  condition:
    any of them
}