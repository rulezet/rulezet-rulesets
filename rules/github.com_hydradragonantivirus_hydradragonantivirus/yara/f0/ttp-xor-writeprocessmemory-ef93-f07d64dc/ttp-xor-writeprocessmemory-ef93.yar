rule TTP_XOR_WriteProcessMemory_ef93 {
  strings:
    $key_ef93 = { b8 e1 [2] 8a c3 [2] 8c f6 [2] a2 f6 [2] 9d ea }

  condition:
    any of them
}