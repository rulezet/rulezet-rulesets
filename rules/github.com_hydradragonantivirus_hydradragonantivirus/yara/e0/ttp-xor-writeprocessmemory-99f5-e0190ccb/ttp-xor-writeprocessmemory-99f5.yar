rule TTP_XOR_WriteProcessMemory_99f5 {
  strings:
    $key_99f5 = { ce 87 [2] fc a5 [2] fa 90 [2] d4 90 [2] eb 8c }

  condition:
    any of them
}