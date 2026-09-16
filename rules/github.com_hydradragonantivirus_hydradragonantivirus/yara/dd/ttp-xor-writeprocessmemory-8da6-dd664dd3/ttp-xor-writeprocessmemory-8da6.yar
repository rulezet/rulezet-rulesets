rule TTP_XOR_WriteProcessMemory_8da6 {
  strings:
    $key_8da6 = { da d4 [2] e8 f6 [2] ee c3 [2] c0 c3 [2] ff df }

  condition:
    any of them
}