rule TTP_XOR_WriteProcessMemory_e593 {
  strings:
    $key_e593 = { b2 e1 [2] 80 c3 [2] 86 f6 [2] a8 f6 [2] 97 ea }

  condition:
    any of them
}