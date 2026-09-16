rule TTP_XOR_WriteProcessMemory_a2ed {
  strings:
    $key_a2ed = { f5 9f [2] c7 bd [2] c1 88 [2] ef 88 [2] d0 94 }

  condition:
    any of them
}