rule TTP_XOR_WriteProcessMemory_8e92 {
  strings:
    $key_8e92 = { d9 e0 [2] eb c2 [2] ed f7 [2] c3 f7 [2] fc eb }

  condition:
    any of them
}