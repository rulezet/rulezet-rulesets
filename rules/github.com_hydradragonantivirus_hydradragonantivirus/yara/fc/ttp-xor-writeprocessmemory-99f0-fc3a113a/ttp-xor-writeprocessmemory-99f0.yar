rule TTP_XOR_WriteProcessMemory_99f0 {
  strings:
    $key_99f0 = { ce 82 [2] fc a0 [2] fa 95 [2] d4 95 [2] eb 89 }

  condition:
    any of them
}