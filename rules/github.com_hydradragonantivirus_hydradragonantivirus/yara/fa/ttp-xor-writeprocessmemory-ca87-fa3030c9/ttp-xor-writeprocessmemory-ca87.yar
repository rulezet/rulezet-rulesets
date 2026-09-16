rule TTP_XOR_WriteProcessMemory_ca87 {
  strings:
    $key_ca87 = { 9d f5 [2] af d7 [2] a9 e2 [2] 87 e2 [2] b8 fe }

  condition:
    any of them
}