rule TTP_XOR_WriteProcessMemory_0485 {
  strings:
    $key_0485 = { 53 f7 [2] 61 d5 [2] 67 e0 [2] 49 e0 [2] 76 fc }

  condition:
    any of them
}