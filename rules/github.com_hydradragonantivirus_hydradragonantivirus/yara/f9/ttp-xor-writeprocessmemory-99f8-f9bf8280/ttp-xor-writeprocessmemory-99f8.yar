rule TTP_XOR_WriteProcessMemory_99f8 {
  strings:
    $key_99f8 = { ce 8a [2] fc a8 [2] fa 9d [2] d4 9d [2] eb 81 }

  condition:
    any of them
}