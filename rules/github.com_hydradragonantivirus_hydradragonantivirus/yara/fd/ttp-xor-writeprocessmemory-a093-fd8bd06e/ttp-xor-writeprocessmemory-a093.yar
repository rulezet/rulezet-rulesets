rule TTP_XOR_WriteProcessMemory_a093 {
  strings:
    $key_a093 = { f7 e1 [2] c5 c3 [2] c3 f6 [2] ed f6 [2] d2 ea }

  condition:
    any of them
}