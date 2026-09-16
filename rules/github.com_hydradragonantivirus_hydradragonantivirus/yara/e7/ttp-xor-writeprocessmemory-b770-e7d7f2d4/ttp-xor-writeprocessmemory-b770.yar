rule TTP_XOR_WriteProcessMemory_b770 {
  strings:
    $key_b770 = { e0 02 [2] d2 20 [2] d4 15 [2] fa 15 [2] c5 09 }

  condition:
    any of them
}