rule TTP_XOR_WriteProcessMemory_ab87 {
  strings:
    $key_ab87 = { fc f5 [2] ce d7 [2] c8 e2 [2] e6 e2 [2] d9 fe }

  condition:
    any of them
}