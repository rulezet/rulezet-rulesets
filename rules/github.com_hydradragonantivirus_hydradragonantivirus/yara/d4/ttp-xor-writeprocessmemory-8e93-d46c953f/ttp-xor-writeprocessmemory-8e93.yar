rule TTP_XOR_WriteProcessMemory_8e93 {
  strings:
    $key_8e93 = { d9 e1 [2] eb c3 [2] ed f6 [2] c3 f6 [2] fc ea }

  condition:
    any of them
}