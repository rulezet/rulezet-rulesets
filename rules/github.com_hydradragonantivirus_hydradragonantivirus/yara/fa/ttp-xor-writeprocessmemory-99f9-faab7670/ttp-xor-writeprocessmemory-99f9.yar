rule TTP_XOR_WriteProcessMemory_99f9 {
  strings:
    $key_99f9 = { ce 8b [2] fc a9 [2] fa 9c [2] d4 9c [2] eb 80 }

  condition:
    any of them
}