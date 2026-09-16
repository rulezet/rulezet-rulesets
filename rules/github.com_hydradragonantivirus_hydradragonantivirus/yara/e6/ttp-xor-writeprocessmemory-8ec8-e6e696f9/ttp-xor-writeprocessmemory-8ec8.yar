rule TTP_XOR_WriteProcessMemory_8ec8 {
  strings:
    $key_8ec8 = { d9 ba [2] eb 98 [2] ed ad [2] c3 ad [2] fc b1 }

  condition:
    any of them
}