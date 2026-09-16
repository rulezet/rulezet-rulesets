rule TTP_XOR_WriteProcessMemory_ef87 {
  strings:
    $key_ef87 = { b8 f5 [2] 8a d7 [2] 8c e2 [2] a2 e2 [2] 9d fe }

  condition:
    any of them
}