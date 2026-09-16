rule TTP_XOR_WriteProcessMemory_a671 {
  strings:
    $key_a671 = { f1 03 [2] c3 21 [2] c5 14 [2] eb 14 [2] d4 08 }

  condition:
    any of them
}