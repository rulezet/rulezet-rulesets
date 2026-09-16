rule TTP_XOR_WriteProcessMemory_99f6 {
  strings:
    $key_99f6 = { ce 84 [2] fc a6 [2] fa 93 [2] d4 93 [2] eb 8f }

  condition:
    any of them
}