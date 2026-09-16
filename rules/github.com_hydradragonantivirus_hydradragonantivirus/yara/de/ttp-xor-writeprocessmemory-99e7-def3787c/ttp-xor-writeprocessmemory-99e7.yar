rule TTP_XOR_WriteProcessMemory_99e7 {
  strings:
    $key_99e7 = { ce 95 [2] fc b7 [2] fa 82 [2] d4 82 [2] eb 9e }

  condition:
    any of them
}