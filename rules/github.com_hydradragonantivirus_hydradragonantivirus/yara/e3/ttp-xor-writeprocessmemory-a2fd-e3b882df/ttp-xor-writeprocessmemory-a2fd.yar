rule TTP_XOR_WriteProcessMemory_a2fd {
  strings:
    $key_a2fd = { f5 8f [2] c7 ad [2] c1 98 [2] ef 98 [2] d0 84 }

  condition:
    any of them
}